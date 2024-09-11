[uwsgi]
http-socket = :{{ UWSGI_PORT }}
chdir = /root/psono
module = wsgi
master = true
log-x-forwarded-for = true
processes = {{ UWSGI_PROCESSES }}

die-on-term = true
buffer-size = {{ UWSGI_BUFFER_SIZE }}
