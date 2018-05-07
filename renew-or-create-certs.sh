#!/bin/bash

# Écrit par Fabien Zouaoui
# Permet de gérer les certificats crées par certbot

WEBROOT='/var/lib/nginx/html'
CERTS_DIR='/etc/letsencrypt/live'
NAMES=${@}

function print_help()
{
	cat <<EOF
	Usage: ${0} FQDN [FQDN ...]

	Le programme va renouveller les certificats pour les fqdns en possèdant déjà un,
	ou en créer de nouveaux de nouveaux s'ils n'en possèdent pas.

	Les secrets correspondants, retrouvés grace au règles ingress, seront remplacés dans l'api kubernetes
	Les secrets ne doivent pas nécessairement exister, mais doivent être configurés dans l'ingress
EOF
}

function die()
{
	[ "${@}" ] && echo -e "${@}" >&2
	exit 1
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
	kubectl create secret generic ${sec} --from-file=tls.crt=${CERTS_DIR}/${name}/fullchain.pem --from-file=tls.key=${CERTS_DIR}/${name}/privkey.pem
}

[ -z "${NAMES}" -o "${NAMES}" = '-h' -o "${NAMES}" = '--help' ] && (print_help && die)

for NAME in ${NAMES} ; do
	if i_have_cert ${NAME} ; then
		update_cert ${NAME}
	else
		create_cert ${NAME}
	fi
	if (( ${?} == 0 )); then
		update_secret ${NAME}
	else
		echo "Erreur lors de la création / renouvellement du certificat" 2>&1
	fi
done
