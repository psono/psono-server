# PSONO Dockerfile for Alpine
FROM psono-docker.jfrog.io/python:alpine3.6

LABEL maintainer="Sascha Pfeiffer <sascha.pfeiffer@psono.com>"
COPY psono/static/email /var/www/html/static/email
COPY . /root/
WORKDIR /root

RUN apk upgrade --no-cache && \
    mkdir -p /root/.pip && \
    echo '[global]' >> /root/.pip/pip.conf && \
    echo 'index-url = https://psono.jfrog.io/psono/api/pypi/pypi/simple' >> /root/.pip/pip.conf && \
    apk add --no-cache \
        curl \
        build-base \
        libffi-dev \
        linux-headers \
        postgresql-dev && \
    pip3 install --upgrade pip && \
    pip3 install -r requirements.txt && \
    pip3 install uwsgi && \
    mkdir -p /root/.psono_server && \
    cp /root/configs/mainconfig/settings.yaml /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresDatabase/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresUser/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresHost/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresPort/5432/g /root/.psono_server/settings.yaml && \
    sed -i s,path/to/psono-server,root,g /root/.psono_server/settings.yaml && \
    apk del --no-cache \
        build-base \
        libffi-dev \
        linux-headers && \
    rm -Rf \
        /root/.cache


HEALTHCHECK --interval=2m --timeout=3s \
	CMD curl -f http://localhost/healthcheck/ || exit 1

EXPOSE 80

CMD ["/bin/sh", "/root/configs/docker/cmd.sh"]
