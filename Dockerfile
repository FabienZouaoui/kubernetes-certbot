FROM		registry.sirdata.fr/alpine-kubectl:v4
MAINTAINER	Fabien Zouaoui <fzo@sirdata.fr>
LABEL		Description="Base alpine with certbot to renew certificates"

RUN mkdir /run/nginx

RUN apk update && \
	apk add certbot nginx bash openssl ca-certificates \
	mariadb-client whois bind-tools wget python3 && \
	update-ca-certificates && \
	rm -f /var/cache/apk/*

RUN pip3 install --upgrade pip && pip3 install kubernetes

COPY run.sh                   /run.sh
COPY renew-or-create-certs.sh /renew-or-create-certs.sh
COPY create-ingress.sh        /create-ingress.sh
COPY template-ingress.yml     /template-ingress.yml
COPY domain-managment.py      /domain-managment.py

ENTRYPOINT ["/bin/sh"]
#ENTRYPOINT ["/usr/sbin/nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"]
#CMD [""]
