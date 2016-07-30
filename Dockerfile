FROM ubuntu:16.04
ENV DEBIAN_FRONTEND noninteractive
MAINTAINER Sascha Pfeiffer <sascha.pfeiffer@psono.com>
COPY . /root/
WORKDIR /root
RUN apt-get update && \
    apt-get install -y libyaml-dev libpython2.7-dev libpq-dev libffi-dev python-dev python-pip python-psycopg2 postgresql-client && \
    pip install -r requirements.txt && \
    apt-get clean && \
    mkdir /root/.password_manager_server && \
    cp /root/configs/mainconfig/settings.yaml /root/.password_manager_server/settings.yaml && \
    sed -i s/YourPostgresDatabase/postgres/g /root/.password_manager_server/settings.yaml && \
    sed -i s/YourPostgresUser/postgres/g /root/.password_manager_server/settings.yaml && \
    sed -i s/YourPostgresHost/db/g /root/.password_manager_server/settings.yaml && \
    sed -i s/YourPostgresPort/5432/g /root/.password_manager_server/settings.yaml && \
    sed -i s,path/to/password-manager-server,root,g /root/.password_manager_server/settings.yaml