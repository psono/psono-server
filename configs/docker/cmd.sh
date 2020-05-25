python3 /root/createconfig.py /root/configs/docker/psono_uwsgi_port.ini.tpl /root/configs/docker/psono_uwsgi_port.ini && \
python3 /root/psono/manage.py migrate && \
uwsgi --ini /root/configs/docker/psono_uwsgi_port.ini