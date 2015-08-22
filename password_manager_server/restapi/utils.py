from django.conf import settings
import bcrypt
import time
import base64

from six import string_types
import sys
if sys.version_info < (2, 7):
    from django.utils.importlib import import_module
else:
    from importlib import import_module


def import_callable(path_or_callable):
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        assert isinstance(path_or_callable, string_types)
        package, attr = path_or_callable.rsplit('.', 1)
        return getattr(import_module(package), attr)

def generate_activation_code(email):
    email = str(email.strip())
    time_stamp = str(int(time.time()))
    return base64.b64encode(
        time_stamp+'.'+bcrypt.hashpw(time_stamp+settings.ACTIVATION_LINK_SECRET+email, bcrypt.gensalt())
    )

def validate_activation_code(email, activation_code):
    time_stamp, hash = base64.b64decode(activation_code).split(".", 1)
    return bcrypt.hashpw(time_stamp + settings.ACTIVATION_LINK_SECRET + email, hash) == hash and int(
        time_stamp) + 60 * settings.ACTIVATION_LINK_TIME_VALID > int(time.time())
