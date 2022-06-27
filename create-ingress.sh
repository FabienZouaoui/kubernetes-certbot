#!/bin/bash

# Écrit par Fabien Zouaoui
# Crée des règles ingress selon une liste de hostname stockés en base

TEMPLATE="$(dirname ${0})/template-ingress.yml"
DEST_DIR='/dev/shm/auto-ingresses'
INGRESS_API_VERSION='extensions/v1beta1'
RUN_KUBECTL=0

function get_hostnames()
{
	mysql -BN \
		-h ${MYSQL_SERVER} \
		-u ${MYSQL_USERNAME} \
		-p${MYSQL_PASSWORD} \
		-e "select ${ROW} from ${TABLE}" \
		${MYSQL_DATABASE}
}

mkdir -p ${DEST_DIR}
rm -f ${DEST_DIR-foolproof}/*
for HOSTNAME in $(get_hostnames); do
	if kubectl get ingress | grep -q "${HOSTNAME}"; then
		echo "Hostname ${HOSTNAME} already has an ingress rule"
		continue
	fi
	ING_NAME=${HOSTNAME//./-}
	SECRET_NAME="${ING_NAME}-tls-secret-ingress"
	sed \
		-e "s/{INGRESS_API_VERSION}/${INGRESS_API_VERSION}/g" \
		-e "s/{ING_NAME}/${ING_NAME}/g" \
		-e "s/{SECRET_NAME}/${SECRET_NAME}/g" \
		-e "s/{HOSTNAME}/${HOSTNAME}/g" \
		${TEMPLATE} > ${DEST_DIR}/${HOSTNAME}.yml
	RUN_KUBECTL=1
done

[ ${RUN_KUBECTL} -eq 1 ] && \
	kubectl create -f ${DEST_DIR}
