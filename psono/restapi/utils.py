from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.core.cache import cache
from django.db import connection

from rest_framework import status as rest_status
import bcrypt
import time
from uuid import UUID
from .models import User, User_Share_Right, Group_Share_Right, Secret_Link, Data_Store, Share_Tree

import nacl.encoding
import nacl.utils
import nacl.secret
import hashlib
import binascii
from yubico_client import Yubico

import pyscrypt

import six
from importlib import import_module


def import_callable(path_or_callable):
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        assert isinstance(path_or_callable, six.string_types)
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
    secret_key = hashlib.sha256(settings.ACTIVATION_LINK_SECRET.encode('utf-8')).hexdigest()
    crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
    validation_secret = crypto_box.encrypt((time_stamp + '#' + email).encode("utf-8"),
                                         nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
    return nacl.encoding.HexEncoder.encode(validation_secret).decode()


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
        secret_key = hashlib.sha256(settings.ACTIVATION_LINK_SECRET.encode('utf-8')).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        validation_secret = crypto_box.decrypt(nacl.encoding.HexEncoder.decode(activation_code)).decode()

        time_stamp, email = validation_secret.split("#", 1)
        if int(time_stamp) + settings.ACTIVATION_LINK_TIME_VALID > int(time.time()):

            email = email.lower().strip()
            email_bcrypt = bcrypt.hashpw(email.encode('utf-8'), settings.EMAIL_SECRET_SALT.encode('utf-8')).decode().replace(settings.EMAIL_SECRET_SALT, '', 1)

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
                ur.id, ur.read, ur.write, ur.grant
            FROM restapi_share_tree t
                JOIN restapi_share_tree t2 ON t2.path @> t.path AND t2.path != t.path
                JOIN restapi_user_share_right ur ON t2.share_id = ur.share_id
            WHERE t.share_id = %(share_id)s
                AND ur.user_id = %(user_id)s
                AND ur.accepted = true
            ORDER BY t.path, nlevel(t.path) - nlevel(t2.path) ASC
        ) a
        UNION
        SELECT DISTINCT ON (id) *
        FROM (
            SELECT DISTINCT ON(t.path)
                gr.id, gr.read, gr.write, gr.grant
            FROM restapi_share_tree t
                JOIN restapi_share_tree t2 ON t2.path @> t.path AND t2.path != t.path
                JOIN restapi_group_share_right gr ON t2.share_id = gr.share_id
                JOIN restapi_user_group_membership gm ON gr.group_id = gm.group_id
            WHERE t.share_id = %(share_id)s
                AND gm.user_id = %(user_id)s
                AND gm.accepted = true
            ORDER BY t.path, nlevel(t.path) - nlevel(t2.path) ASC
        ) b
        """, {
        'share_id': share_id,
        'user_id': user_id,
    })


def get_all_direct_user_rights(user_id, share_id):

    try:
        user_share_rights = User_Share_Right.objects.only("read", "write", "grant").filter(user_id=user_id, share_id=share_id, accepted=True)
    except User_Share_Right.DoesNotExist:
        user_share_rights = []

    return user_share_rights


def get_all_direct_group_rights(user_id, share_id):

    return Group_Share_Right.objects.raw("""SELECT gr.id, gr.read, gr.write, gr.grant
        FROM restapi_group_share_right gr
            JOIN restapi_user_group_membership ms ON gr.group_id = ms.group_id
        WHERE gr.share_id = %(share_id)s
            AND ms.user_id = %(user_id)s
            AND ms.accepted = true""", {
        'share_id': share_id,
        'user_id': user_id,
    })


def calculate_user_rights_on_share(user_id = -1, share_id=-1):
    """
    Calculates the user's rights on a share

    :param user_id:
    :type user_id:
    :param share_id:
    :type share_id:
    :return:
    :rtype:
    """

    grouped_read = False
    grouped_write = False
    grouped_grant = False

    has_direct_user_share_rights = False
    has_direct_group_share_rights = False

    user_rights = get_all_direct_user_rights(user_id=user_id, share_id=share_id)

    for user_right in user_rights:
        has_direct_user_share_rights = True
        grouped_read = grouped_read or user_right.read
        grouped_write = grouped_write or user_right.write
        grouped_grant = grouped_grant or user_right.grant


    group_rights = get_all_direct_group_rights(user_id, share_id)

    for s in group_rights:
        has_direct_group_share_rights = True
        grouped_read = grouped_read or s.read
        grouped_write = grouped_write or s.write
        grouped_grant = grouped_grant or s.grant


    if has_direct_user_share_rights == False and has_direct_group_share_rights == False:

        # maybe the user has inherited rights
        user_share_rights = get_all_inherited_rights(user_id, share_id)

        for s in user_share_rights:
            grouped_read = grouped_read or s.read
            grouped_write = grouped_write or s.write
            grouped_grant = grouped_grant or s.grant

    return {
        'read': grouped_read,
        'write': grouped_write,
        'grant': grouped_grant,
    }


def user_has_rights_on_share(user_id = -1, share_id=-1, read=None, write=None, grant=None):
    """
    Checks if the given user has the requested rights for the given share.
    User_share_rights and all Group_share_rights be checked first.

    If "right = true" is demanded and one of them is true, this function returns true.
    If "right = false" is demanded and one of them is true, this function returns false.

    Afterwards inherited rights are checked.

    If "right = true" is demanded and one of them is true, this function returns true.
    If "right = false" is demanded and one of them is true, this function returns false.

    :param user_id:
    :param share_id:
    :param read:
    :param write:
    :param grant:
    :return:
    """

    rights = calculate_user_rights_on_share(user_id, share_id)

    return (read is None or read == rights['read']) \
           and (write is None or write == rights['write']) \
           and (grant is None or grant == rights['grant'])


def user_has_rights_on_secret(user_id = -1, secret_id=-1, read=None, write=None):
    """
    Checks if the given user has the requested rights for the given secret

    :param user_id:
    :param secret_id:
    :param read:
    :param write:
    :return:
    """

    datastores_loaded = False
    datastores = []

    try:
        # get all secret links. Get the ones with datastores as parents first, as they are less expensive to check later
        secret_links = Secret_Link.objects.filter(secret_id=secret_id).order_by('parent_datastore_id')
    except Secret_Link.DoesNotExist:
        return False

    for link in secret_links:

        if link.parent_datastore_id is not None:
            if not datastores_loaded:
                try:
                    datastores = Data_Store.objects.filter(user_id=user_id).values_list('id', flat=True).all()
                except Data_Store.DoesNotExist:
                    datastores = []
                datastores_loaded = True

            if link.parent_datastore_id in datastores:
                return True

        elif link.parent_share_id is not None and user_has_rights_on_share(user_id, link.parent_share_id, read, write):
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

    salt = hashlib.sha512(username.lower().encode('utf-8')).hexdigest()

    return binascii.hexlify(pyscrypt.hash(password=password.encode("utf-8"),
                         salt=salt.encode("utf-8"),
                         N=16384,
                         r=8,
                         p=1,
                         dkLen=64))

def get_datastore(datastore_id=None, user=None):
    """
    Returns for a given datastore ID and user the datastore (if the user owns the datastore) or None (if the user doesn't
    own the datastore)

    :param datastore_id: The datastore ID
    :type datastore_id: uuid
    :param user: The user and alleged owner of the datastore
    :type user: User
    :return:
    :rtype:
    """

    if user and not datastore_id:
        try:
            datastores = Data_Store.objects.filter(user=user)
        except Data_Store.DoesNotExist:
            datastores = []
        return datastores

    datastore = None
    try:
        if user and datastore_id:
            datastore = Data_Store.objects.get(pk=datastore_id, user=user)
        else:
            datastore = Data_Store.objects.get(pk=datastore_id)
    except Data_Store.DoesNotExist:
        pass
    except ValueError:
        pass

    return datastore


def readbuffer(data):
    """
    Reads an arbitary data objects and returns the byte representation (in python 3) or str (in python2)
    :param data:
    :type data:
    :return:
    :rtype:
    """
    if not data:
        return six.b('')
    if str(type(data)) == "<type 'buffer'>":
        return str(data)
    elif str(type(data)) == "<class 'memoryview'>":
        return data.tobytes().decode()
    else:
        return str(data).encode("utf-8")


def create_share_link(link_id, share_id, parent_share_id, parent_datastore_id):
    """
    DB wrapper to create a link between a share and a datastore or another (parent-)share and the correct creation of
    link paths to their children

    Takes care of "degenerated" tree structures (e.g a child has two parents)

    In addition checks if the link already exists, as this is a crucial part of the access rights system

    :param link_id:
    :param share_id:
    :param parent_share_id:
    :param parent_datastore_id:
    :return:
    """

    link_id = str(link_id).replace("-", "")

    # Prevent malicious (or by bad RNGs generated?) link ids
    # Not doing so could cause access rights problems
    if Share_Tree.objects.filter(path__match='*.' + link_id + '.*').count() > 0:
        return False

    cursor = connection.cursor()

    cursor.execute("""INSERT INTO restapi_share_tree (id, create_date, write_date, path, share_id, parent_share_id, parent_datastore_id)
    SELECT
      gen_random_uuid() id,
      now() create_date,
      now() write_date,
      CASE
        WHEN nlevel(one_old_parent.path) = nlevel(t.path) THEN COALESCE(new_parent.path, '') || %(link_id)s
        ELSE coalesce(new_parent.path, '') || %(link_id)s || subltree(t.path, nlevel(one_old_parent.path), nlevel(t.path))
      END path,
      t.share_id,
      CASE
        WHEN nlevel(one_old_parent.path) = nlevel(t.path) THEN new_parent.share_id
        ELSE t.parent_share_id
      END parent_share_id,
      CASE
        WHEN nlevel(one_old_parent.path) = nlevel(t.path) AND new_parent.share_id IS NOT NULL THEN NULL
        WHEN nlevel(one_old_parent.path) != nlevel(t.path) AND t.parent_share_id IS NOT NULL THEN NULL
        WHEN nlevel(one_old_parent.path) = nlevel(t.path) THEN COALESCE(%(parent_datastore_id)s, t.parent_datastore_id) --replace this null with datastore id if specified
        ELSE t.parent_datastore_id
      END parent_datastore_id
    FROM restapi_share_tree t
    JOIN (
      SELECT path
      FROM restapi_share_tree
      WHERE share_id = %(share_id)s
      LIMIT 1
    ) one_old_parent ON t.path <@ one_old_parent.path
    LEFT JOIN restapi_share_tree new_parent
      ON new_parent.share_id = %(parent_share_id)s""", {
        'parent_datastore_id': parent_datastore_id,
        'link_id': link_id,
        'share_id': share_id,
        'parent_share_id': parent_share_id,
    })

    if cursor.rowcount == 0:
        if parent_datastore_id:
            Share_Tree.objects.create(
                share_id=share_id,
                parent_datastore_id=parent_datastore_id,
                path=link_id
            )
        else:
            cursor.execute("""INSERT INTO restapi_share_tree (id, create_date, write_date, path, share_id, parent_share_id, parent_datastore_id)
            SELECT
                gen_random_uuid() id,
                now() create_date,
                now() write_date,
                path || %(link_id)s path,
                %(share_id)s share_id,
                %(parent_share_id)s parent_share_id,
                %(parent_datastore_id)s parent_datastore_id
                FROM restapi_share_tree
                WHERE share_id = %(parent_share_id)s""", {
                'link_id': link_id,
                'parent_share_id': parent_share_id,
                'parent_datastore_id': parent_datastore_id,
                'share_id': share_id,
            })

    return True

def delete_share_link(link_id):
    """
    DB wrapper to delete a link to a share (and all his child shares with the same link)

    :param link_id:
    :return:
    """

    link_id = str(link_id).replace("-", "")

    Share_Tree.objects.filter(path__match='*.'+link_id+'.*').delete()