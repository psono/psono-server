python3 /root/psono/manage.py migrate && \
cd /root/psono && \
daphne -b 0.0.0.0 -p 80 asgi:application