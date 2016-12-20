FROM ubuntu:16.04
ENV DEBIAN_FRONTEND noninteractive
MAINTAINER Sascha Pfeiffer <sascha.pfeiffer@psono.com>
COPY password_manager_server/static/email /var/www/html/static/email
COPY . /root/
WORKDIR /root
RUN apt-get update && \
    apt-get install -y \
        libyaml-dev \
        libpython2.7-dev \
        libpq-dev \
        libffi-dev \
        python-dev \
        python-pip \
        python-psycopg2 \
        nginx \
        supervisor \
        postgresql-client \
        cron \
        net-tools && \
    pip install -r requirements.txt && \
    pip install uwsgi && \
    apt-get clean && \
    mkdir /root/.psono_server && \
    echo "daemon off;" >> /etc/nginx/nginx.conf && \
    cp /root/configs/docker/worker-cron /etc/cron.d/ && \
    chmod 0644 /etc/cron.d/worker-cron && \
    touch /var/log/cron.log && \
    mkdir /var/www/html/media && \
    cp /root/configs/docker/supervisor-psono-server.conf /etc/supervisor/conf.d/ && \
    cp /root/configs/docker/supervisor-psono-worker.conf /etc/supervisor/conf.d/ && \
    cp /root/configs/nginx/docker-psono.pw.conf /etc/nginx/sites-available/default && \
    cp /root/configs/mainconfig/settings.yaml /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresDatabase/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresUser/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresHost/postgres/g /root/.psono_server/settings.yaml && \
    sed -i s/YourPostgresPort/5432/g /root/.psono_server/settings.yaml && \
    sed -i s,path/to/psono-server,root,g /root/.psono_server/settings.yaml

EXPOSE 80

CMD bash -c "supervisord -n"