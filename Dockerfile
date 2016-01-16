FROM ubuntu:14.04
ENV DEBIAN_FRONTEND noninteractive
MAINTAINER Sascha Pfeiffer <saschapfeiffer@sanso.pw>
COPY . /root/
WORKDIR /root
RUN apt-get update && \
    apt-get install -y libyaml-dev libpython2.7-dev libpq-dev libffi-dev python-dev python-pip python-psycopg2 && \
    pip install -r requirements.txt && \
    apt-get clean && \
    mkdir .password_manager_server && \
    cp configs/mainconfig/settings.yaml .password_manager_server/settings.yaml && \
    sed -i s/YourPostgresDatabase/postgres/g .password_manager_server/settings.yaml && \
    sed -i s/YourPostgresUser/postgres/g .password_manager_server/settings.yaml && \
    sed -i s/YourPostgresHost/db/g .password_manager_server/settings.yaml && \
    sed -i s/YourPostgresPort/5432/g .password_manager_server/settings.yaml && \
    sed -i s/DEBUG:\ True/DEBUG:\ False/g .password_manager_server/settings.yaml