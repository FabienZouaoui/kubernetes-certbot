FROM		registry.sirdata.fr/alpine-kubectl:v29
MAINTAINER	Fabien Zouaoui <fzo@sirdata.fr>
LABEL		Description="Base alpine with certbot to renew certificates"

RUN mkdir -p /run/nginx

#RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories
RUN apk update && \
	apk add nginx bash openssl ca-certificates \
	mariadb-client whois bind-tools wget python3 py3-pip && \
	rm -f /var/cache/apk/* && \
	update-ca-certificates

RUN apk add gcc python3-dev musl-dev libffi-dev openssl-dev rust cargo \
	py3-six py3-requests py3-distro && rm -f /var/cache/apk/*
RUN pip3 install --upgrade pip
RUN pip3 install --upgrade cryptography
RUN pip3 install --no-cache certbot
RUN rm -rf /root/.cache
RUN apk del gcc python3-dev musl-dev libffi-dev openssl-dev py3-pip rust cargo && \
	rm -f /var/cache/apk/*

COPY run.sh                   /run.sh
COPY renew-or-create-certs.sh /renew-or-create-certs.sh
COPY create-ingress.sh        /create-ingress.sh
COPY template-ingress.yml     /template-ingress.yml
COPY domain-managment.py      /domain-managment.py

ENTRYPOINT ["/bin/sh"]
#ENTRYPOINT ["/usr/sbin/nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"]
#CMD [""]
