import sys
import os
from django.template import Engine, Context

def get_config_vars():

    config_vars = {
        'UWSGI_PORT': os.environ.get('UWSGI_PORT', '80'),
        'UWSGI_PROCESSES': os.environ.get('UWSGI_PROCESSES', '10'),
        'UWSGI_BUFFER_SIZE': os.environ.get('UWSGI_BUFFER_SIZE', '8192'),
        'NGINX_STRICT_TRANSPORT_SECURITY': os.environ.get('NGINX_STRICT_TRANSPORT_SECURITY', ''),
        'NGINX_HEADER_REFERRER_POLICY': os.environ.get('NGINX_HEADER_REFERRER_POLICY', 'same-origin'),
        'NGINX_HEADER_X_FRAME_OPTIONS': os.environ.get('NGINX_HEADER_X_FRAME_OPTIONS', 'DENY'),
        'NGINX_HEADER_X_CONTENT_TYPE_OPTIONS': os.environ.get('NGINX_HEADER_X_CONTENT_TYPE_OPTIONS', 'nosniff'),
        'NGINX_HEADER_X_XSS_PROTECTION': os.environ.get('NGINX_HEADER_X_XSS_PROTECTION', '"1; mode=block"'),
        'NGINX_HEADER_CONTENT_SECURITY_POLICY': os.environ.get('NGINX_HEADER_CONTENT_SECURITY_POLICY', '''"default-src 'none'; manifest-src 'self'; connect-src 'self' https://keyserver.ubuntu.com https://storage.googleapis.com https://*.s3.amazonaws.com https://*.digitaloceanspaces.com https://api.pwnedpasswords.com https://sentry.io; font-src 'self'; img-src 'self' www.google-analytics.com data:; script-src 'self' www.google-analytics.com; style-src 'self' 'unsafe-inline'; object-src 'self'; form-action 'self'"'''),
    }

    return config_vars

def main(src, dst):

    with open(src, 'r') as myfile:
        input = myfile.read()

    template = Engine().from_string(input)
    config_vars = get_config_vars()
    context = Context(config_vars)

    output_from_parsed_template = template.render(context)
    # print(output_from_parsed_template)

    with open(dst, "w") as fh:
        fh.write(output_from_parsed_template)

if __name__ == "__main__":
    src = sys.argv[1]
    dst = sys.argv[2]

    main(src, dst)
