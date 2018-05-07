#!/bin/bash

#TODO: Ajouter des gardes fou supplémentaires pour ne pas se faire blacklister par letsencrypt (voir leur CGU)

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

CUSTOM_DNS_SRV='8.8.8.8'
TMP_INGRESS_DIR='/dev/shm/auto-ingresses'
ING_TEMPLATE="$(dirname ${0})/template-ingress.yml"
TMP_CERTFILE='/dev/shm/certfile'
WEBROOT='/var/lib/nginx/html'
CERTS_DIR='/etc/letsencrypt/live'
COLLECTOR_DIR='/var/lib/node_exporter_collector'
declare -i LOOP_NUM=0

declare HOSTNAMES

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
	
	test -d ${CERTS_DIR} || \
		die "Error: ${CERTS_DIR} directory is unavailable"
	
	test -f ${ING_TEMPLATE} || \
		die "Error: ${ING_TEMPLATE} file is unavailable"
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

	mysql -BN \
		-h ${MYSQL_SERVER} \
		-u ${MYSQL_USERNAME} \
		-p${MYSQL_PASSWORD} \
		-e "update ${TABLE} set ${AVAIL_ROW} = 1 WHERE domain_name = '${hostname}' " \
		${MYSQL_DATABASE}
}

function generate_ingress_file()
{
	local hostname=${1}
	local ingname=${hostname//./-}
	local secretname="${ingname}-tls-secret-ingress"
	local template=${2}

	sed \
		-e "s/{ING_NAME}/${ingname}/g" \
		-e "s/{SECRET_NAME}/${secretname}/g" \
		-e "s/{HOSTNAME}/${hostname}/g" \
		\
		${template}
}

function check_hostname()
{
	local hostname=${1}

	host ${hostname} ${CUSTOM_DNS_SRV} &> /dev/null
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

function check_certificate_expiration()
{
	local secret=${1}
	local hostname=${2}
	local ingress=${3}
	local expire

	kubectl get secrets ${secret} -o yaml \
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
	[ -d ${CERTS_DIR}/${1} ]
}

function update_cert()
{
	#certbot renew
	certbot certonly -n --text --webroot --webroot-path ${WEBROOT} -d ${1}
}

function create_cert()
{
	certbot certonly --text --webroot --webroot-path ${WEBROOT} -d ${1}
}

function update_secret()
{
	local name=${1}
	local ing
	local sec

	[ -f ${CERTS_DIR}/${name}/fullchain.pem -a -f ${CERTS_DIR}/${name}/privkey.pem ] \
		|| die "Impossible d'accèder au certificat et/ou à la clé"

	ing=$(kubectl get ingress | awk -v NAME=${name} '($2==NAME) {print $1}')
	[ -z "${ing}" ] && die "Impossible de trouver la regle ingress pour ${name}"

	sec=$(kubectl get ingress ${ing} --output=jsonpath="{..secretName}")
	[ -z "${sec}" ] && die "Impossible de trouver le secret ${name} (ingress ${ing})"

	kubectl delete secret ${sec} 2> /dev/null
	kubectl create secret generic ${sec} \
		--from-file=tls.crt=${CERTS_DIR}/${name}/fullchain.pem \
		--from-file=tls.key=${CERTS_DIR}/${name}/privkey.pem
}

echo "Sleeping a bit to avoid restart storm"
sleep 15
check_prerequesties
restart_nginx

# Create an arbitrary file to check that queries to hostnames are reaching this pod
mkdir -p ${WEBROOT}/.well-known/acme-challenge
echo 'ok' > ${WEBROOT}/.well-known/acme-challenge/$(hostname).txt

while true; do
	((LOOP_NUM++))
	echo 'Generating needed ingress rules from database'
	mkdir -p ${TMP_INGRESS_DIR}
	rm -f ${TMP_INGRESS_DIR-foolproof}/*
	RUN_KUBECTL=0
	for HOST_NAME in $(get_needed_hostnames); do
		if echo ${HOST_NAME} | grep -qE ${SIRDATA_DOMAINS_PATTERN}; then
			if ! check_hostname ${HOST_NAME}; then
				echo "Hostname ${HOST_NAME} does not resolve"

                                DOMAIN=$(extract_domain_name ${HOST_NAME})
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
			fi
		fi
		check_hostname ${HOST_NAME} && update_hostname_status ${HOST_NAME}

		if kubectl get ingress | grep -q "${HOST_NAME}"; then
			echo "Hostname ${HOST_NAME} already has an ingress rule"
			continue
		fi
		generate_ingress_file ${HOST_NAME} ${ING_TEMPLATE} \
			> ${TMP_INGRESS_DIR}/${HOST_NAME}.yml
		RUN_KUBECTL=1

	done
	[ ${RUN_KUBECTL} -eq 1 ] && \
		kubectl create -f ${TMP_INGRESS_DIR}

	HOSTNAMES=''
	for ingress in $(kubectl get ingress -o jsonpath="{..metadata.name}"); do
		echo ''
		rm -f ${TMP_CERTFILE}

		HOST_NAME=$(kubectl get ingress ${ingress} -o jsonpath="{..rules..host}")
		if [ -z "${HOST_NAME}" ]; then
			echo "Unable to find hostname for ingress \"${ingress}\""
			continue
		fi

		SECRET=$(kubectl get ingress ${ingress} -o jsonpath="{..tls..secretName}" 2> /dev/null)
		if [ -z "${SECRET}" ]; then
			echo "Unable to find secret name for ingress \"${ingress}\""
			continue
		fi

		if ! $(wget --no-check-certificate -q --spider http://${HOST_NAME}/.well-known/acme-challenge/$(hostname).txt 2> /dev/null); then
			echo "Could not validate that \"${HOST_NAME}\" is pointing to me. Aborting !"
			continue
		fi

		check_certificate_expiration ${SECRET} ${HOST_NAME} ${ingress} \
			|| continue

		HOSTNAMES+=" ${HOST_NAME}"
	done

	if [ -n "${HOSTNAMES}" ]; then
		echo -e "\n\nRenewing or creating cert(s) for ${HOSTNAMES}"
		for HOST_NAME in ${HOSTNAMES}; do
			if i_have_cert ${HOST_NAME} ; then
				update_cert ${HOST_NAME}
			else
				create_cert ${HOST_NAME}
			fi
			if (( ${?} == 0 )); then
				update_secret ${HOST_NAME}
			else
				echo "Erreur lors de la création / renouvellement du certificat" 2>&1
			fi
		done
	else
		echo -e "\n\nNothing to do :)"
	fi

	echo "certbot_run_time{ret=\"0\"} $(date +%s)" \
		>> ${COLLECTOR_DIR}/certbot_run_time.prom.$$
	mv ${COLLECTOR_DIR}/certbot_run_time.prom.$$ ${COLLECTOR_DIR}/certbot_run_time.prom

	(( ${LOOP_NUM} >= ${LOOP_COUNT} )) && exit 0

	echo -e "\nSleeping for ${LOOP_SLEEP_TIME} seconds"
	sleep ${LOOP_SLEEP_TIME}
done
