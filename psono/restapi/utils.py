from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.core.cache import cache
import bcrypt
import time
from uuid import UUID
from models import User, User_Share_Right, Secret_Link, Data_Store

import nacl.encoding
import nacl.utils
import nacl.secret
import hashlib
from yubico_client import Yubico

import pyscrypt

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
    Takes email address and combines it with a timestamp before encrypting everything with the ACTIVATION_LINK_SECRET
    No database storage required for this action

    :param email: email
    :type email: unicode
    :return: activation_code
    :rtype: str
    """

    email = str(email).lower().strip()
    time_stamp = str(int(time.time()))

    # normally encrypt emails, so they are not stored in plaintext with a random nonce
    secret_key = hashlib.sha256(settings.ACTIVATION_LINK_SECRET).hexdigest()
    crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
    validation_secret = crypto_box.encrypt(time_stamp + '#' + email,
                                         nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
    return nacl.encoding.HexEncoder.encode(validation_secret)


def validate_activation_code(activation_code):
    """
    Validate activation codes for the given time specified in settings ACTIVATION_LINK_TIME_VALID
    without database reference, based on salsa20. Returns the user or False in case of a failure

    :param activation_code: activation_code
    :type activation_code: str
    :return: user or False
    :rtype: User or bool
    """

    try:
        secret_key = hashlib.sha256(settings.ACTIVATION_LINK_SECRET).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        validation_secret = crypto_box.decrypt(nacl.encoding.HexEncoder.decode(activation_code))

        time_stamp, email = validation_secret.split("#", 1)
        if int(time_stamp) + settings.ACTIVATION_LINK_TIME_VALID > int(time.time()):

            email = email.lower().strip()
            email_bcrypt = bcrypt.hashpw(email.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)

            return User.objects.filter(email_bcrypt=email_bcrypt, is_email_active=False)[0]
    except:
        #wrong format or whatever could happen
        pass

    return False

def authenticate(username = False, user = False, authkey = False):
    """
    Checks if the authkey for the given user, specified by the email or directly by the user object matches

    :param username: str
    :param user: User
    :param authkey: str
    :return: user or False
    :rtype: User or bool
    """

    if not authkey:
        return False
    if not username and not user:
        return False

    if username:
        try:
            user = User.objects.filter(username=username, is_active=True)[0]
        except IndexError:
            return False

    if not check_password(authkey, user.authkey):
        return False

    return user


def get_all_inherited_rights(user_id, share_id):

    return User_Share_Right.objects.raw("""SELECT DISTINCT ON (id) *
        FROM (
          SELECT DISTINCT ON(t.path)
          ur.*
        FROM restapi_share_tree t
        JOIN restapi_share_tree t2 ON t2.path @> t.path AND t2.path != t.path
        JOIN restapi_user_share_right ur ON t2.share_id = ur.share_id
        WHERE t.share_id = %(share_id)s
          AND ur.user_id = %(user_id)s
          AND ur.accepted = true
        ORDER BY t.path, nlevel(t.path) - nlevel(t2.path) ASC
        ) a""", {
        'share_id': share_id,
        'user_id': user_id,
    })


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
        user_share_right = User_Share_Right.objects.get(user_id=user_id, share_id=share_id, accepted=True)

        return (read is None or read == user_share_right.read)\
               and (write is None or write == user_share_right.write)\
               and (grant is None or grant == user_share_right.grant)

    except User_Share_Right.DoesNotExist:
        # maybe he has inherited rights
        user_share_rights = get_all_inherited_rights(user_id, share_id)

        grouped_read = False
        grouped_write = False
        grouped_grant = False

        for s in user_share_rights:
            grouped_read = grouped_read or s.read
            grouped_write = grouped_write or s.write
            grouped_grant = grouped_grant or s.grant

        return (read is None or read == grouped_read) \
               and (write is None or write == grouped_write) \
               and (grant is None or grant == grouped_grant)


def user_has_rights_on_secret(user_id = -1, secret_id=-1, read=None, write=None):
    """
    Checks if the given user has the requested rights for the given secret

    :param user_id:
    :param secret_id:
    :param read:
    :param write:
    :return:
    """

    try:
        datastores = Data_Store.objects.filter(user_id=user_id).values_list('id', flat=True)
    except Data_Store.DoesNotExist:
        datastores = []

    try:
        # get all secret links. Get the ones with datastores as parents first, as they are less expensive to check later
        secret_links = Secret_Link.objects.filter(secret_id=secret_id).order_by('parent_datastore_id')
    except Secret_Link.DoesNotExist:
        return False

    for link in secret_links:
        if link.parent_share_id is not None and user_has_rights_on_share(user_id, link.parent_share_id, read, write):
            return True
        elif link.parent_datastore_id is not None and link.parent_datastore_id in datastores:
            return True

    return False

def get_cache(model, pk):
    pk = str(pk)
    try:
        cached_entity = None
        if settings.CACHE_ENABLE:
            cached_entity = cache.get('psono_' + model._meta.verbose_name + '_' + pk)

        if cached_entity is None:
            entity = model.objects.get(pk=pk)
            if entity.is_cachable:
                set_cache(entity, entity.get_cache_time())
        else:
            entity = cached_entity
    except model.DoesNotExist:
        return None

    return entity

def set_cache(obj, timeout=None):
    pk = str(obj.pk)
    if settings.CACHE_ENABLE:
        cache.set('psono_' + obj._meta.verbose_name + '_' + pk, obj, timeout)

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

def request_misses_uuid(request, attribute):
    """
    check if a given request misses an attribute or the attribute is not valid uuid
    
    :param request: The request to check
    :type request: 
    :param attribute: The Attribute to check
    :type attribute: str
    :return: True or False
    :rtype: bool
    """

    return attribute not in request.data or not is_uuid(request.data[attribute])


def yubikey_authenticate(yubikey_otp):
    """
    Checks a YubiKey OTP
    
    :param yubikey_otp: Yubikey OTP
    :type yubikey_otp: 
    :return: True or False or None
    :rtype: bool
    """

    if settings.YUBIKEY_CLIENT_ID is None or settings.YUBIKEY_SECRET_KEY is None:
        return None

    client = Yubico(settings.YUBIKEY_CLIENT_ID, settings.YUBIKEY_SECRET_KEY)
    try:
        yubikey_is_valid = client.verify(yubikey_otp)
    except:
        yubikey_is_valid = False

    return yubikey_is_valid

def yubikey_get_yubikey_id(yubikey_otp):
    """
    Returns the yubikey id based
    
    :param yubikey_otp: Yubikey OTP
    :type yubikey_otp: str
    :return: Yubikey ID
    :rtype: str
    """

    yubikey_otp = str(yubikey_otp).strip()

    return yubikey_otp[:12]

def generate_authkey(username, password):
    """
    Generates the authkey that is sent to the server instead of the cleartext password

    :param username: The username of the user
    :type username: str
    :param password: The password of the user
    :type password: str
    :return: authkey: The authkey of the user
    :rtype: str
    """

    salt = hashlib.sha512(username.lower()).hexdigest()

    return pyscrypt.hash(password=password,
                         salt=salt,
                         N=16384,
                         r=8,
                         p=1,
                         dkLen=64).encode('hex')