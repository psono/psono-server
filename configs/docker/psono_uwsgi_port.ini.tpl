[uwsgi]
http-socket = :{{ UWSGI_PORT }}
chdir = /root/psono
module = wsgi
master = true
processes = {{ UWSGI_PROCESSES }}

die-on-term = true
