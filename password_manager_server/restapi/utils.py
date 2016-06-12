from django.conf import settings
from django.contrib.auth.hashers import check_password
import bcrypt
import time
import base64
from uuid import UUID
from models import User, User_Share_Right

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
        email+','+time_stamp+','+bcrypt.hashpw(time_stamp+settings.ACTIVATION_LINK_SECRET+email, bcrypt.gensalt())
    )

def validate_activation_code(activation_code):
    """
    Validate activation codes for the given time specified in settings ACTIVATION_LINK_TIME_VALID
    without database reference, based on bcrypt. Returns the user or False in case of a failure

    :param activation_code: activation_code
    :type activation_code: str
    :return: user or False
    :rtype: User or bool
    """

    try:
        email, time_stamp, hash = base64.b64decode(activation_code).split(",", 2)
        if bcrypt.hashpw(time_stamp + settings.ACTIVATION_LINK_SECRET + email, hash) == hash and int(
            time_stamp) + settings.ACTIVATION_LINK_TIME_VALID > int(time.time()):
            return User.objects.filter(email=email, is_email_active=False)[0]
    except:
        #wrong format or whatever could happen
        pass

    return False

def authenticate(email = False, user = False, authkey = False):
    """
    Checks if the authkey for the given user, specified by the email or directly by the user object matches

    :param email: str
    :param user: User
    :param authkey: str
    :return: user or False
    :rtype: User or bool
    """

    if not authkey:
        return False
    if not email and not user:
        return False

    if email:
        try:
            user = User.objects.filter(email=email, is_active=True)[0]
        except IndexError:
            return False

    if not check_password(authkey, user.authkey):
        return False

    return user


def user_has_rights_on_share(user_id = -1, share_id=-1, read=None, write=None, grant=None):
    """
    Checks if the given user has the requested rights for the given share

    :param user_id:
    :param share_id:
    :param read:
    :param write:
    :param grant:
    :return:
    """

    try:
        # check direct share_rights first, as direct share_rights override inherited share rights
        user_share_right = User_Share_Right.objects.get(share_id=share_id, user_id=user_id)

        return (read is None or read == user_share_right.read)\
               and (write is None or write == user_share_right.write)\
               and (grant is None or grant == user_share_right.grant)

    except User_Share_Right.DoesNotExist:
        # maybe he has inherited rights
        return False

def is_uuid(expr):
    """
    check if a given expression is a uuid (version 4)

    :param expr: the possible uuid
    :return: True or False
    :rtype: bool
    """

    try:
        val = UUID(expr, version=4)
    except ValueError:
        val = False

    return not not val

