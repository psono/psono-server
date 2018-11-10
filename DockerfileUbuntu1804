# PSONO Dockerfile for Ubuntu 18.04
FROM psono-docker.jfrog.io/ubuntu:18.04
ENV DEBIAN_FRONTEND noninteractive
LABEL maintainer="Sascha Pfeiffer <sascha.pfeiffer@psono.com>"
COPY psono/static/email /var/www/html/static/email
COPY . /root/
WORKDIR /root

RUN mkdir -p /root/.pip && \
    echo '[global]' >> /root/.pip/pip.conf && \
    echo 'index-url = https://psono.jfrog.io/psono/api/pypi/pypi/simple' >> /root/.pip/pip.conf && \
    apt-get update && \
    apt-get install -y \
        haveged \
        libyaml-dev \
        libpython3-dev \
        libpq-dev \
        libffi-dev \
        libssl-dev \
        python3-dev \
        python3-pip \
        python3-psycopg2 \
        postgresql-client && \
    pip3 install -r requirements.txt && \
    pip3 install uwsgi && \
    mkdir -p /root/.psono_server && \
    cp /root/configs/mainconfig/settings.yaml /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresDatabase/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresUser/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresHost/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresPort/5432/g /root/.psono_server/settings.yaml && \
    sed -i s,path/to/psono-server,root,g /root/.psono_server/settings.yaml && \
    apt-get purge -y \
        python3-pip && \
    apt-get clean && \
    rm -Rf /root/var && \
    rm -Rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache

EXPOSE 80

CMD ["/bin/sh", "/root/configs/docker/cmd.sh"]