#!/bin/bash

# Écrit par Fabien Zouaoui
# Gère la création et le renouvellement de domaines et certficats

# Vars defined in kube file
declare -a NEEDED_VARS
NEEDED_VARS+=('MIN_EXPIRATION')
NEEDED_VARS+=('LOOP_SLEEP_TIME')
NEEDED_VARS+=('LOOP_COUNT')
NEEDED_VARS+=('NAME_ROW')
NEEDED_VARS+=('AVAIL_ROW')
NEEDED_VARS+=('TABLE')
NEEDED_VARS+=('SIRDATA_DOMAINS_PATTERN')
NEEDED_VARS+=('MYSQL_SERVER')
NEEDED_VARS+=('MYSQL_USERNAME')
NEEDED_VARS+=('MYSQL_PASSWORD')
NEEDED_VARS+=('MYSQL_DATABASE')
NEEDED_VARS+=('GANDI_API_KEY')
NEEDED_VARS+=('GANDI_HANDLE')
NEEDED_VARS+=('CNAME_TARGET')
NEEDED_VARS+=('GET_HOSTS_FROM_MYSQL')
NEEDED_VARS+=('NS_FOR_MYSQL_HOSTS')
NEEDED_VARS+=('CONTACT_EMAIL')

CUSTOM_DNS_SRV='1.1.1.1'
TMP_INGRESS_DIR='/dev/shm/auto-ingresses'
ING_TEMPLATE="$(dirname ${0})/template-ingress.yml"
TMP_CERTFILE='/dev/shm/certfile'
WEBROOT='/var/lib/nginx/html'
declare -A CERTS_DIR
CERTS_DIR['letsencrypt']='/etc/letsencrypt/live'
#CERTS_DIR['ssl.com']='/etc/ssl-com/live'
COLLECTOR_DIR='/var/lib/node_exporter_collector'
DEFAULT_INGRESS_API_VERSION='extensions/v1beta1'
declare -i LOOP_NUM=0
declare -i RET_VALUE=0

declare HOSTNAMES
declare INGRESS_API_VERSION
declare -A NAMESPACES
declare -A INGRESS_NAMES
declare -A ERRONEOUS_PARTNERS_HOSTNAMES
declare -A PARTNERS_HOSTNAMES
declare -A SSL_PROVIDER

function die()
{
	[ "${@}" ] && echo ${@} >&2
	stop_nginx
	echo "certbot_run_time{ret=\"1\"} $(date +%s)" \
		>> ${COLLECTOR_DIR}/certbot_run_time.prom.$$
	mv ${COLLECTOR_DIR}/certbot_run_time.prom.$$ ${COLLECTOR_DIR}/certbot_run_time.prom
	exit 1
}

function check_prerequesties()
{
	local var
	local err_mess="Error, one or more var is not set:"
	local -a err

	for var in ${NEEDED_VARS[*]}; do
		[ -z "${!var}" ] && \
			err+=(${var})
	done

	(( "${#err[*]}" )) > 0 && \
		die "Error, the following variables are not set: ${err[*]}"
	
	for provider in ${!CERTS_DIR[*]}; do
		test -d ${CERTS_DIR[${provider}]} || \
			die "Error: ${CERTS_DIR[${provider}]} directory is unavailable"
	done
	
	test -f ${ING_TEMPLATE} || \
		die "Error: ${ING_TEMPLATE} file is unavailable"

	test -z "${INGRESS_API_VERSION}" && \
		INGRESS_API_VERSION="${DEFAULT_INGRESS_API_VERSION}"
}

function stop_nginx()
{
	echo "Killing nginx instance"
	/usr/sbin/nginx -s stop
	while $(pidof nginx &> /dev/null); do
		sleep 1
	done
}

function restart_nginx()
{
	stop_nginx

	cat <<EOF > /etc/nginx/conf.d/default.conf
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        location = /404.html {
                internal;
        }
}
EOF
	echo "Starting nginx server"
	/usr/sbin/nginx -c /etc/nginx/nginx.conf
}

function get_needed_hostnames()
{
	${GET_HOSTS_FROM_MYSQL} || return 0

	mysql -BN \
		-h ${MYSQL_SERVER} \
		-u ${MYSQL_USERNAME} \
		-p${MYSQL_PASSWORD} \
		-e "select ${NAME_ROW} from ${TABLE}" \
		${MYSQL_DATABASE}
}

function update_hostname_status()
{
        local hostname=${1}
	local status=${2}

	(( ${status} == 1 )) || echo "Marking ${hostname} as non active"

	mysql -BN \
		-h ${MYSQL_SERVER} \
		-u ${MYSQL_USERNAME} \
		-p${MYSQL_PASSWORD} \
		-e "update ${TABLE} set ${AVAIL_ROW} = ${status} WHERE domain_name = '${hostname}' " \
		${MYSQL_DATABASE}
}

function generate_ingress_file()
{
	local namespace=${1}
	local hostname=${2}
	local ingname=${hostname//./-}
	local secretname="${ingname}-tls-secret-ingress"
	local template=${3}

	sed \
		-e "s/{INGRESS_API_VERSION}/${INGRESS_API_VERSION}/g" \
		-e "s/{ING_NAME}/${ingname}/g" \
		-e "s/{SECRET_NAME}/${secretname}/g" \
		-e "s/{HOSTNAME}/${hostname}/g" \
		\
		${template}
}

function check_hostname()
{
	local hostname=${1}

	#if ! host ${hostname} ${CUSTOM_DNS_SRV} &> /dev/null ; then
	if ! host ${hostname} &> /dev/null ; then
		echo "Could not resolve ${hostname}"
		return 1
	fi

	# Unfortunatelly, some partners are using reverse proxies to redirect traffic to us, so we should only verifiy this when we own the domain
	if [ "$2" == 'CNAME' -a "$(host -t CNAME ${hostname} | awk -v HOSTNAME="${hostname}" '($1==HOSTNAME) {print $6}')" != "${CNAME_TARGET}." ]; then 
		echo "${hostname} is not a CNAME pointing to ${CNAME_TARGET}."
		return 1
	fi
	
	[ "${2}" == 'DNSONLY' -o "${2}" == 'CNAME' ] && return 0

	if [ "$(wget --no-check-certificate --timeout=1 --tries=3 --retry-on-host-error -q -O - https://${hostname}/.well-known/acme-challenge/$(hostname).txt 2> /dev/null)" != 'ok' ]; then
		echo "Could not download https://${hostname}/.well-known/acme-challenge/$(hostname).txt"
		return 1
	fi
}

function extract_domain_name()
{
	local hostname=${1}
	local tld=${hostname##*.}
	local domain_part=${hostname%.*}

	echo "${domain_part##*.}.${tld}"
}

function domain_is_registered()
{
        local domain=${1}

	whois ${domain} | grep -qE 'Domain Name:|domain:'
}

function domain_need_renewal()
{
	local domain=${1}
	local expire=$(date -d $(whois ${domain} | awk -F ':' '($1~"^ *Registry Expiry Date") {gsub("T.*$", "", $2) ; print $2}') +%s)

	if [ -z "${expire}" ]; then
		echo "Unable to find expiration date for this domain. Skipping renewal"
		return 1
	fi
	
	if (( (${expire} - $(date +%s)) < ${MIN_EXPIRATION} )); then
		return 0
	fi
	
	return 1
}

function check_certificate_expiration()
{
	local namespace=${1}
	local secret=${2}
	local hostname=${3}
	local ingress=${4}
	local expire

	kubectl --namespace=${namespace} get secrets ${secret} -o yaml \
		| awk '($1=="tls.crt:") { print $2}' \
		| base64 -d \
		> ${TMP_CERTFILE}

	if ((${?} == 0)); then
		echo "Secret \"${secret}\" found for hostname ${hostname} (ingress ${ingress}). Analysing expiration date"
		expire=$(openssl x509 -in ${TMP_CERTFILE} -text -noout \
			| awk '($1=="Not" && $2=="After") { print $4 " " $5 " " $6 " " $7}')

		if [ -n "${expire}" ]; then
			if (( ($(date -d "${expire}" +%s) - $(date +%s)) > ${MIN_EXPIRATION}  )); then
				echo "Certificate expiration date is too far in the future (${expire}). Skipping"
				return 1
			fi
			echo "Certificate expire in less than ${MIN_EXPIRATION} seconds. Renewing it..."
		else
			echo "Unable to find expiration date in certificate. We will generate a new one"
		fi
	else
		echo "Secret not found for hostname ${hostname} (ingress ${ingress}). We will create a new one"
	fi

	return 0
}

function i_have_cert()
{
	local hostname=${1}
	local provider=${2}

	[ -d ${CERTS_DIR[${provider}]}/${hostname} ]
}

function update_cert()
{
	local hostname=${1}
	local provider=${2}

	if [[ "${provider}" == 'ssl.com' ]]; then
		certbot certonly -n -m ${SSLCOM_EMAIL} --text --config-dir /etc/ssl-com --logs-dir /var/log/ssl-com --webroot --webroot-path ${WEBROOT} \
			--eab-kid ${SSLCOM_ACCOUNT_KEY} --eab-hmac-key ${SSLCOM_HMAC_KEY} --server https://acme.ssl.com/sslcom-dv-rsa -d ${hostname}
		return ${?}
	fi

	#certbot certonly -n --text --preferred-chain "DST Root CA X3" --webroot --webroot-path ${WEBROOT} -d ${hostname}
	certbot certonly -n --text --webroot --webroot-path ${WEBROOT} -d ${hostname}
}

function create_cert()
{
	local hostname=${1}
	local provider=${2}

	if [[ "${provider}" == 'ssl.com' ]]; then
		certbot certonly -n -m ${SSLCOM_EMAIL} --agree-tos --no-eff-email --text \
			--config-dir /etc/ssl-com --logs-dir /var/log/ssl-com --webroot --webroot-path ${WEBROOT} \
			--eab-kid ${SSLCOM_ACCOUNT_KEY} --eab-hmac-key ${SSLCOM_HMAC_KEY} --server https://acme.ssl.com/sslcom-dv-rsa -d ${hostname}
		return ${?}
	fi

	#certbot certonly -n -m ${CONTACT_EMAIL} --agree-tos --no-eff-email --text --preferred-chain "DST Root CA X3" --webroot --webroot-path ${WEBROOT} -d ${hostname}
	certbot certonly -n -m ${CONTACT_EMAIL} --agree-tos --no-eff-email --text --webroot --webroot-path ${WEBROOT} -d ${hostname}
}

function update_secret()
{
	local namespace=${1}
	local ing=${2}
	local host_name=${3}
	local provider=${4}
	local sec

	[ -f ${CERTS_DIR[${provider}]}/${host_name}/fullchain.pem -a -f ${CERTS_DIR[${provider}]}/${host_name}/privkey.pem ] \
		|| die "Impossible d'accèder au certificat et/ou à la clé"

	#ing=$(kubectl --namespace=${namespace} get ingress \
	#	-o custom-columns="NAME:..metadata.name,HOSTS:..spec.rules[0].host" --no-headers \
	#	| awk -v NAME=${host_name} '($2==NAME) {print $1}')
	#[ -z "${ing}" ] && die "Impossible de trouver la regle ingress pour ${host_name}"

	sec=$(kubectl --namespace=${namespace} get ingress ${ing} --output=jsonpath="{..secretName}")
	[ -z "${sec}" ] && die "Impossible de trouver le secret ${host_name} (ingress ${ing})"

	kubectl --namespace=${namespace} delete secret ${sec} 2> /dev/null
	kubectl --namespace=${namespace} create secret generic ${sec} \
		--from-file=tls.crt=${CERTS_DIR[${provider}]}/${host_name}/fullchain.pem \
		--from-file=tls.key=${CERTS_DIR[${provider}]}/${host_name}/privkey.pem
}

function disable_withelist_source_range()
{
	local namespace=${1}
	local ingress=${2}
	local ranges

	ranges=$(kubectl --namespace=${namespace} get ingress ${ingress} \
		--output=jsonpath="{.metadata.annotations.nginx\.ingress\.kubernetes\.io/whitelist-source-range}" \
		2> /dev/null)

	if [[ -n "${ranges}" && "${ranges%% *}" != 'Error' ]]; then
		echo "Disabling withelist source range annotation for ingress ${ingress} in namespace ${namespace}" >&2
		kubectl --namespace=${namespace} annotate ingress ${ingress} nginx.ingress.kubernetes.io/whitelist-source-range- >&2
		sleep 10
		echo ${ranges}
		return 0
	fi
}

function reenable_withelist_source_range()
{
	local namespace=${1}
	local ingress=${2}
	local ranges=${3}

	[ -z "${ranges}" ] && return 0

	echo "Re-enabling withelist source range annotation for ingress ${ingress} in namespace ${namespace}"
	kubectl --namespace=${namespace} annotate ingress ${ingress} nginx.ingress.kubernetes.io/whitelist-source-range=${ranges}
}

check_prerequesties
restart_nginx
echo "Sleeping a bit to avoid restart storm and letting ingress to redirect traffic here"
sleep 75

# Create an arbitrary file to check that queries to hostnames are reaching this pod
mkdir -p ${WEBROOT}/.well-known/acme-challenge
echo 'ok' > ${WEBROOT}/.well-known/acme-challenge/$(hostname).txt

(( ${DEBUG:-0} > 0)) && set -x

while true; do
	((LOOP_NUM++))
	echo 'Generating needed ingress rules from database'
	mkdir -p ${TMP_INGRESS_DIR}
	rm -f ${TMP_INGRESS_DIR-foolproof}/*
	RUN_KUBECTL=0
	unset ERRONEOUS_PARTNERS_HOSTNAMES
	RET_VALUE=0
	declare -A ERRONEOUS_PARTNERS_HOSTNAMES
	for HOST_NAME in $(get_needed_hostnames); do
		PARTNERS_HOSTNAMES["${HOST_NAME}"]='yes'
		CHECK_MODE='full'
		sleep 1
		if echo ${HOST_NAME} | grep -qE ${SIRDATA_DOMAINS_PATTERN}; then

			DOMAIN=$(extract_domain_name ${HOST_NAME})
			if ! check_hostname ${HOST_NAME} 'CNAME'; then

				if ! domain_is_registered ${DOMAIN}; then
					echo "Domain is not registered. Trying to register it"
                                        /domain-managment.py \
                                            --api_key "${GANDI_API_KEY}" \
                                            --handle  "${GANDI_HANDLE}" \
                                            --domain  "${DOMAIN}" \
                                            --action  'register'
				fi

				echo "Adding entry to domain"
                                /domain-managment.py \
                                    --api_key "${GANDI_API_KEY}" \
                                    --handle  "${GANDI_HANDLE}" \
                                    --domain "${DOMAIN}" \
                                    --action 'add_record' \
                                    --record "${HOST_NAME%%.*}" \
                                    --rtype   'CNAME' \
                                    --rtarget "${CNAME_TARGET}"

			elif domain_need_renewal ${DOMAIN}; then
				/domain-managment.py \
					--api_key "${GANDI_API_KEY}" \
					--handle  "${GANDI_HANDLE}" \
					--domain "${DOMAIN}" \
					--action 'renew'
			fi
		fi

		if ! kubectl --namespace=${NS_FOR_MYSQL_HOSTS} get ingress | grep -q "${HOST_NAME}"; then
			generate_ingress_file ${NS_FOR_MYSQL_HOSTS} ${HOST_NAME} ${ING_TEMPLATE} \
				> ${TMP_INGRESS_DIR}/${HOST_NAME}.yml
			RUN_KUBECTL=1
			CHECK_MODE='DNSONLY'
		fi

		if check_hostname ${HOST_NAME} ${CHECK_MODE}; then
			update_hostname_status ${HOST_NAME} 1
		else
			update_hostname_status ${HOST_NAME} 0
			ERRONEOUS_PARTNERS_HOSTNAMES["${HOST_NAME}"]='error'
		fi
	done
	[ ${RUN_KUBECTL} -eq 1 ] && \
		kubectl create -f ${TMP_INGRESS_DIR}

	HOSTNAMES=''
	for namespace in $(kubectl get namespaces -o jsonpath="{..metadata.name}"); do
		[ -z "$(kubectl --namespace=${namespace} get ingress)" ] && continue
		for ingress in $(kubectl --namespace=${namespace} get ingress -o jsonpath="{..metadata.name}"); do
			echo ''
			rm -f ${TMP_CERTFILE}

			HOST_NAME=$(kubectl --namespace=${namespace} get ingress ${ingress} -o jsonpath="{..rules..host}")
			if [ -z "${HOST_NAME}" ]; then
				echo "Unable to find hostname for ingress \"${ingress}\""
				continue
			fi

			SECRET=$(kubectl --namespace=${namespace} get ingress ${ingress} -o jsonpath="{..tls..secretName}" 2> /dev/null)
			if [ -z "${SECRET}" ]; then
				echo "Unable to find secret name for ingress \"${ingress}\""
				continue
			fi
			ssl_provider=$(kubectl --namespace=${namespace} get ingress ${ingress} -o jsonpath="{.metadata.annotations.ssl-provider}" 2> /dev/null)
			if (( ${?} != 0 )); then
				ssl_provider=''
			fi

			if [[ "${ERRONEOUS_PARTNERS_HOSTNAMES[${HOST_NAME}]}" == 'error' ]]; then
				echo "Skipping ${HOST_NAME} due to previous error !"
				#RET_VALUE=1 # Some hosts are unconfigured for a long time, so I'm stopping to consider this an error.
				continue
			fi

			check_certificate_expiration ${namespace} ${SECRET} ${HOST_NAME} ${ingress} \
				|| continue

			whitelist_ranges=$(disable_withelist_source_range ${namespace} ${ingress})
			if ! check_hostname ${HOST_NAME} ; then
				[ "${PARTNERS_HOSTNAMES[${HOST_NAME}]}" != 'yes' ] && \
					echo "Please check that  ingress for \"${HOST_NAME}\" is still needed"
				RET_VALUE=1
				reenable_withelist_source_range ${namespace} ${ingress} ${whitelist_ranges}
				continue
			fi
			reenable_withelist_source_range ${namespace} ${ingress} ${whitelist_ranges}

			HOSTNAMES+=" ${HOST_NAME}"
			NAMESPACES[${HOST_NAME}]=${namespace}
			INGRESS_NAMES[${HOST_NAME}]=${ingress}
			SSL_PROVIDER[${HOST_NAME}]=${ssl_provider:-letsencrypt}
		done
	done

	if [ -n "${HOSTNAMES}" ]; then
		echo -e "\n\nRenewing or creating cert(s) for ${HOSTNAMES}"
		for HOST_NAME in ${HOSTNAMES}; do
			whitelist_ranges=$(disable_withelist_source_range ${NAMESPACES[${HOST_NAME}]} ${INGRESS_NAMES[${HOST_NAME}]})
			if i_have_cert ${HOST_NAME} ${SSL_PROVIDER[${HOST_NAME}]} ; then
				update_cert ${HOST_NAME} ${SSL_PROVIDER[${HOST_NAME}]}
			else
				create_cert ${HOST_NAME} ${SSL_PROVIDER[${HOST_NAME}]}
			fi
			if (( ${?} == 0 )); then
				update_secret ${NAMESPACES[${HOST_NAME}]} ${INGRESS_NAMES[${HOST_NAME}]} ${HOST_NAME} ${SSL_PROVIDER[${HOST_NAME}]}
			else
				RET_VALUE=1
				echo "Erreur lors de la création / renouvellement du certificat" 2>&1
			fi
			reenable_withelist_source_range ${NAMESPACES[${HOST_NAME}]} ${INGRESS_NAMES[${HOST_NAME}]} ${whitelist_ranges}
		done
	else
		echo -e "\n\nNothing to do :)"
	fi


	for CLUSTER in $(grep search /etc/resolv.conf); do
		true
	done
	[ -z "${CLUSTER}" ] && CLUSTER='unknown'

	echo "certbot_run_time{cluster=\"${CLUSTER}\",ret=\"${RET_VALUE}\"} $(date +%s)" \
		>> ${COLLECTOR_DIR}/certbot_run_time.prom.$$
	mv ${COLLECTOR_DIR}/certbot_run_time.prom.$$ ${COLLECTOR_DIR}/certbot_run_time.prom

	(( ${LOOP_NUM} >= ${LOOP_COUNT} )) && exit 0

	echo -e "\nSleeping for ${LOOP_SLEEP_TIME} seconds"
	sleep ${LOOP_SLEEP_TIME}
done
