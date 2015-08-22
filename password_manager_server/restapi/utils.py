from django.conf import settings
from django.contrib.auth.hashers import check_password
import bcrypt
import time
import base64
from models import Content_Storage_Owner

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
    """
    Takes email address and combines it with a secret in settings ACTIVATION_LINK_SECRET and the
    current timestamp in seconds to a hash based on bcrypt and base64 encoding without database backend

    :param email: activation_code
    :type email: unicode
    :return: activation_code
    :rtype: str
    """
    email = str(email.strip())
    time_stamp = str(int(time.time()))
    return base64.b64encode(
        base64.b64encode(email)+'.'+time_stamp+'.'+bcrypt.hashpw(time_stamp+settings.ACTIVATION_LINK_SECRET+email, bcrypt.gensalt())
    )

def validate_activation_code(activation_code):
    """
    Validate activation codes for the given time specified in settings ACTIVATION_LINK_TIME_VALID
    without database reference, based on bcrypt. Returns the owner or False in case of a failure

    :param activation_code: activation_code
    :type activation_code: str
    :return: content_storage_owner or False
    :rtype: Content_Storage_Owner or bool
    """
    try:
        email, time_stamp, hash = base64.b64decode(activation_code).split(".", 2)
        email = base64.b64decode(email)
        if bcrypt.hashpw(time_stamp + settings.ACTIVATION_LINK_SECRET + email, hash) == hash and int(
            time_stamp) + 60 * settings.ACTIVATION_LINK_TIME_VALID > int(time.time()):
            return Content_Storage_Owner.objects.filter(email=email, is_email_active=False)[0]
        return False

    except:
        #wrong format or whatever could happen
        return False

def authenticate(email = False, owner = False, authkey = False):
    """
    Checks if the authkey for the given owner, specified by the email or directly by the owner object matches

    :param email: str
    :param owner: Content_Storage_Owner
    :param authkey: str
    :return: content_storage_owner or False
    :rtype: Content_Storage_Owner or bool
    """
    if not authkey:
        return False
    if not email and not owner:
        return False

    if email:
        try:
            owner = Content_Storage_Owner.objects.filter(email=email, is_active=True)[0]
        except IndexError:
            return False

    if not check_password(authkey, owner.authkey):
        return False

    return owner