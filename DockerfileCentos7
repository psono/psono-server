# PSONO Dockerfile for CentOS 7
FROM psono-docker.jfrog.io/centos:centos7

LABEL maintainer="Sascha Pfeiffer <sascha.pfeiffer@psono.com>"
COPY psono/static/email /var/www/html/static/email
COPY . /root/
WORKDIR /root

RUN mkdir -p /root/.pip && \
    echo '[global]' >> /root/.pip/pip.conf && \
    echo 'index-url = https://psono.jfrog.io/psono/api/pypi/pypi/simple' >> /root/.pip/pip.conf && \
    yum -y update && \
    yum -y install https://centos7.iuscommunity.org/ius-release.rpm && \
    yum -y update && \
    yum -y install \
        gcc \
        haveged \
        libffi-devel \
        openssl-devel \
        postgresql \
        postgresql-devel \
        python36u \
        python36u-devel \
        python36u-pip && \
    pip3.6 install -r requirements.txt && \
    pip3.6 install uwsgi && \
    pip3.6 install typing && \
    mkdir -p /root/.psono_server && \
    cp /root/configs/mainconfig/settings.yaml /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresDatabase/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresUser/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresHost/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresPort/5432/g /root/.psono_server/settings.yaml && \
    sed -i s,path/to/psono-server,root,g /root/.psono_server/settings.yaml && \
    yum remove -y \
        python36u-pip && \
    yum clean all && \
    rm -Rf \
        /root/requirements.txt \
        /root/var \
        /root/.cache \
        /tmp/* \
        /var/tmp/*

EXPOSE 80

CMD ["/bin/sh", "/root/configs/docker/cmd.sh"]