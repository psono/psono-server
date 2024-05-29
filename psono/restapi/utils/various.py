from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.cache import cache
from django.db import connection
from urllib.parse import urlparse

from typing import Optional
import os

import bcrypt
import time
from ..models import User, User_Share_Right, Group_Share_Right, Secret_Link, File_Link, Data_Store, Share_Tree, Duo, Google_Authenticator, Yubikey_OTP, default_hashing_parameters
from ..models import File_Repository_Right
from .avatar import delete_avatar_storage_of_user

from nacl.public import PrivateKey
import nacl.secret
import nacl.encoding
import nacl.utils
import hashlib
import binascii
import ipaddress

from uuid import UUID

import scrypt
from typing import Tuple, List

import json


def generate_activation_code(email: str) -> str:
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
    secret_key = hashlib.sha256(settings.ACTIVATION_LINK_SECRET.encode()).hexdigest()
    crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
    validation_secret = crypto_box.encrypt((time_stamp + '#' + email).encode("utf-8"),
                                         nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
    return nacl.encoding.HexEncoder.encode(validation_secret).decode()


def get_static_bcrypt_hash_from_email(email):
    """
    Takes an email address. Removes all leading and trailing whitespaces and casts it to lowercase.

    Returns the case invariant hash without the static salt.

    :param email:
    :type email:
    :return:
    :rtype:
    """
    email = email.lower().strip().encode()
    email_salt = settings.EMAIL_SECRET_SALT.encode()
    bcrypt_with_salt = bcrypt.hashpw(email, email_salt).decode()

    return bcrypt_with_salt.replace(settings.EMAIL_SECRET_SALT, '', 1)


def validate_activation_code(activation_code: str) -> Optional[User]:
    """
    Validate activation codes for the given time specified in settings ACTIVATION_LINK_TIME_VALID
    without database reference, based on salsa20. Returns the user or False in case of a failure

    :param activation_code: activation_code
    :type activation_code: str
    :return: user
    :rtype: User or None
    """

    try:
        secret_key = hashlib.sha256(settings.ACTIVATION_LINK_SECRET.encode()).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        validation_secret = crypto_box.decrypt(nacl.encoding.HexEncoder.decode(activation_code)).decode()

        time_stamp, email = validation_secret.split("#", 1)
        if int(time_stamp) + settings.ACTIVATION_LINK_TIME_VALID > int(time.time()):

            email_bcrypt = get_static_bcrypt_hash_from_email(email)

            return User.objects.filter(email_bcrypt=email_bcrypt, is_email_active=False)[0]
    except:  # nosec
        #wrong format or whatever could happen
        pass

    return None

def authenticate(username: str = "", user: User = None, authkey: str = "", password: str = "") -> Tuple: # nosec
    """
    Checks if the authkey for the given user, specified by the email or directly by the user object matches

    :param username: str
    :param user: User
    :param authkey: str
    :param password: str or False
    :return: user or False
    :rtype: User or bool, str
    """

    if not username and not user:
        return False, 'USER_NOT_PROVIDED'

    if not authkey:
        return False, 'AUTHKEY_NOT_PROVIDED'

    error_code = 'USER_NOT_FOUND'

    for method in settings.AUTHENTICATION_METHODS:
        if 'AUTHKEY' == method:
            if username and not user:
                try:
                    user = User.objects.filter(username=username, is_active=True, authentication='AUTHKEY')[0]
                except IndexError:
                    continue

            if user and user.authkey is not None:
                if check_password(authkey, user.authkey):
                    return user, None
                else:
                    error_code = 'INCORRECT_PASSWORD'

    return False, error_code


def get_all_inherited_rights(user_id: str, share_id: str) -> User_Share_Right:

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


def get_all_direct_user_rights(user_id: str, share_id: str) -> User_Share_Right:

    try:
        user_share_rights = User_Share_Right.objects.only("read", "write", "grant").filter(user_id=user_id, share_id=share_id, accepted=True)
    except User_Share_Right.DoesNotExist:
        user_share_rights = []

    return user_share_rights


def get_all_direct_group_rights(user_id: str, share_id: str) -> Group_Share_Right:

    return Group_Share_Right.objects.raw("""SELECT gr.id, gr.read, gr.write, gr.grant
        FROM restapi_group_share_right gr
            JOIN restapi_user_group_membership ms ON gr.group_id = ms.group_id
        WHERE gr.share_id = %(share_id)s
            AND ms.user_id = %(user_id)s
            AND ms.accepted = true""", {
        'share_id': share_id,
        'user_id': user_id,
    })


def calculate_user_rights_on_share(user_id: str = "", share_id: str = "") -> dict:
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


def user_has_rights_on_share(user_id: str = "", share_id: str = "", read: bool = None, write: bool = None, grant: bool = None) -> bool:
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


def user_has_rights_on_secret(user_id: str = "", secret_id: str = "", read: bool = None, write: bool = None) -> bool:  #nosec B105, B107
    """
    Checks if the given user has the requested rights for the given secret

    :param user_id:
    :param secret_id:
    :param read:
    :param write:
    :return:
    """

    datastores_loaded = False
    datastores = []  # type: List[str]

    try:
        # get all secret links. Get the ones with datastores as parents first, as they are less expensive to check later
        secret_links = Secret_Link.objects.only('parent_datastore_id', 'parent_share_id').filter(secret_id=secret_id).order_by('parent_datastore_id')
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


def calculate_user_rights_on_file_repository(user_id: str = "", file_repository_id: str = ""):
    grouped_shared = False
    grouped_read = False
    grouped_write = False
    grouped_grant = False

    user_rights = File_Repository_Right.objects.filter(user_id=user_id, file_repository_id=file_repository_id, accepted=True).all()

    for user_right in user_rights:
        grouped_shared = True
        grouped_read = grouped_read or user_right.read
        grouped_write = grouped_write or user_right.write
        grouped_grant = grouped_grant or user_right.grant


    group_rights = File_Repository_Right.objects.raw("""SELECT gfrr.id, gfrr.read, gfrr.write, gfrr.grant
        FROM restapi_group_file_repository_right gfrr
            JOIN restapi_user_group_membership ms ON ms.group_id = gfrr.group_id
        WHERE gfrr.file_repository_id = %(file_repository_id)s
            AND ms.user_id = %(user_id)s
            AND ms.accepted = true""", {
        'file_repository_id': file_repository_id,
        'user_id': user_id,
    })

    for s in group_rights:
        grouped_shared = True
        grouped_read = grouped_read or s.read
        grouped_write = grouped_write or s.write
        grouped_grant = grouped_grant or s.grant


    return {
        'shared': grouped_shared,
        'read': grouped_read,
        'write': grouped_write,
        'grant': grouped_grant,
    }


def user_has_rights_on_file_repository(user_id: str = "", file_repository_id: str = "", read: bool = None, write: bool = None, grant: bool = None) -> bool:
    """
    Checks if the given user has the requested rights for the given file repository

    :param user_id:
    :param file_repository_id:
    :param read:
    :param write:
    :param grant:
    :return:
    """

    rights = calculate_user_rights_on_file_repository(user_id, file_repository_id)

    return (read is None or read == rights['read']) \
           and (write is None or write == rights['write']) \
           and (grant is None or grant == rights['grant'])

def user_has_rights_on_file(user_id: str = "", file_id: str = "", read: bool = None, write: bool = None) -> bool:
    """
    Checks if the given user has the requested rights for the given file

    :param user_id:
    :param file_id:
    :param read:
    :param write:
    :return:
    """

    datastores_loaded = False
    datastores = [] # type: List[str]

    try:
        # get all file links. Get the ones with datastores as parents first, as they are less expensive to check later
        file_links = File_Link.objects.only('parent_datastore_id', 'parent_share_id').filter(file_id=file_id).order_by('parent_datastore_id')
    except File_Link.DoesNotExist:
        return False

    for link in file_links:

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


def generate_authkey(username, password, u, r, p, l) -> bytes:
    """
    Generates the authkey that is sent to the server instead of the cleartext password

    :param username: The username of the user
    :type username: str
    :param password: The password of the user
    :type password: str
    :param u:
    :type u: int
    :param r:
    :type r: int
    :param p:
    :type p: int
    :param l:
    :type l: int

    :return: authkey: The authkey of the user
    :rtype: authkey str
    """

    salt = hashlib.sha512(username.lower().encode()).hexdigest()

    return binascii.hexlify(scrypt.hash(password=password.encode("utf-8"),
                                        salt=salt.encode("utf-8"),
                                        N=pow(2, u),
                                        r=r,
                                        p=p,
                                        buflen=l))


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
        return Data_Store.objects.filter(user=user)

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



def encrypt_symmetric(secret_key, msg):
    """
    Encrypts a message with a secret hex encoded key and an automatically generated random nonce

    :param secret_key: hex encoded secret key
    :type secret_key: str or bytearray
    :param msg: The message to encrypt
    :type msg: bytearray

    :return: The encrypted value
    :rtype: dict
    """
    # generate random nonce
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    # open crypto box with session secret
    secret_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)

    # encrypt msg with crypto box and nonce
    encrypted = secret_box.encrypt(msg, nonce)

    # cut away the nonce
    text = encrypted[len(nonce):]

    # convert nonce and encrypted msg to hex
    nonce_hex = nacl.encoding.HexEncoder.encode(nonce)
    text_hex = nacl.encoding.HexEncoder.encode(text)

    return {'text': text_hex, 'nonce': nonce_hex}


def encrypt_secret(secret, password, user_sauce, u, r, p, l) -> Tuple[bytes, bytes]:
    """
    Encrypts a secret with a password and a random static user specific key we call "user_sauce"

    :param secret: The secret to encrypt
    :type secret: bytes
    :param password: The password to use for the encryption
    :type password: str
    :param user_sauce: A random static user specific key
    :type user_sauce: bytes
    :param u:
    :type u: int
    :param r:
    :type r: int
    :param p:
    :type p: int
    :param l:
    :type l: int

    :return: A tuple of the encrypted secret and nonce
    :rtype: (bytes, bytes)
    """

    salt = hashlib.sha512(user_sauce).hexdigest()

    k = hashlib.sha256(binascii.hexlify(scrypt.hash(password=password.encode("utf-8"),
                                                    salt=salt.encode("utf-8"),
                                                    N=pow(2, u),
                                                    r=r,
                                                    p=p,
                                                    buflen=l))).hexdigest()
    crypto_box = nacl.secret.SecretBox(k, encoder=nacl.encoding.HexEncoder)

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted_secret_full = crypto_box.encrypt(secret, nonce)
    encrypted_secret = encrypted_secret_full[len(nonce):]

    return nacl.encoding.HexEncoder.encode(encrypted_secret), nacl.encoding.HexEncoder.encode(nonce)


def decrypt_secret(encrypted_secret_hex, encrypted_secret_hex_nonce, password, user_sauce, u, r, p, l) -> bytes:
    """
    Decrypts a secret with a password and a random static user specific key we call "user_sauce"

    :param encrypted_secret_hex: The secret to decrypt
    :type encrypted_secret_hex: bytes
    :param encrypted_secret_hex_nonce: The nonce for the secret to decrypt
    :type encrypted_secret_hex_nonce: bytes
    :param password: The password to use for the encryption
    :type password: str
    :param user_sauce: A random static user specific key
    :type user_sauce: bytes
    :param u:
    :type u: int
    :param r:
    :type r: int
    :param p:
    :type p: int
    :param l:
    :type l: int

    :return: The decrypted secret
    :rtype: bytes
    """

    salt = hashlib.sha512(user_sauce).hexdigest()

    k = hashlib.sha256(binascii.hexlify(scrypt.hash(password=password.encode("utf-8"),
                                                    salt=salt.encode("utf-8"),
                                                    N=pow(2, u),
                                                    r=r,
                                                    p=p,
                                                    buflen=l))).hexdigest()
    crypto_box = nacl.secret.SecretBox(k, encoder=nacl.encoding.HexEncoder)

    decrypted_secret = crypto_box.decrypt(encrypted_secret_hex, encrypted_secret_hex_nonce)

    return decrypted_secret


def delete_user(username: str) -> dict:
    """
    Deletes a user by its username

    :param username:
    :type username:
    :return:
    :rtype:
    """
    try:
        user = User.objects.get(username=username.lower())
    except User.DoesNotExist:
        return {
            'error': 'User does not exist'
        }

    delete_avatar_storage_of_user(user.id)

    user.delete()

    return {}

def promote_user(username: str, role: str) -> dict:
    try:
        user = User.objects.get(username=username.lower())
    except User.DoesNotExist:
        return {
            'error': 'User does not exist'
        }

    if role == 'superuser':
        user.is_superuser = True
        user.save()
    else:
        return {
            'error': 'Role does not exist'
        }

    return {}

def reset_2fa(username: str) -> dict:
    """
    Resets all second factors for a given user

    :param username:
    :type username: str

    :return:
    :rtype: dict
    """
    try:
        user = User.objects.get(username=username.lower())
    except User.DoesNotExist:
        return {
            'error': 'User does not exist'
        }

    user.duo_enabled = False
    user.google_authenticator_enabled = False
    user.yubikey_otp_enabled = False
    user.webauthn_enabled = False
    user.save()

    Duo.objects.filter(user_id=user.id).delete()
    Google_Authenticator.objects.filter(user_id=user.id).delete()
    Yubikey_OTP.objects.filter(user_id=user.id).delete()

    return {}

def demmote_user(username: str, role: str) -> dict:
    try:
        user = User.objects.get(username=username.lower())
    except User.DoesNotExist:
        return {
            'error': 'User does not exist'
        }

    if role == 'superuser':
        user.is_superuser = False
        user.save()
    else:
        return {
            'error': 'Role does not exist'
        }

    return {}

def enable_user(username: str) -> dict:
    try:
        user = User.objects.get(username=username.lower())
    except User.DoesNotExist:
        return {
            'error': 'User does not exist'
        }

    user.is_active = True
    user.save()

    return {}

def disable_user(username: str) -> dict:
    try:
        user = User.objects.get(username=username.lower())
    except User.DoesNotExist:
        return {
            'error': 'User does not exist'
        }

    user.is_active = False
    user.save()

    return {}

def verify_user_email(username: str) -> dict:
    try:
        user = User.objects.get(username=username.lower())
    except User.DoesNotExist:
        return {
            'error': 'User does not exist'
        }

    user.is_email_active = True
    user.save()

    return {}

def encrypt_with_db_secret(plain_text: str) -> str:
    """
    Encrypts plain text with the db secret

    :param plain_text: The decrypted plain text
    :type plain_text: str
    :return: encrypted text as hex
    :rtype: str
    """
    secret_key = hashlib.sha256(settings.DB_SECRET.encode()).hexdigest()
    crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
    encrypted_data = crypto_box.encrypt(plain_text.encode(),
                                         nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))

    return nacl.encoding.HexEncoder.encode(encrypted_data).decode()

def decrypt_with_db_secret(encrypted_text: str) -> str:
    """
    Decrypts encrypted text with the db secret

    :param encrypted_text: The decrypted plain text in hex
    :type encrypted_text: str
    :return: decrypted text
    :rtype: str
    """
    secret_key = hashlib.sha256(settings.DB_SECRET.encode()).hexdigest()
    crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
    plaintext = crypto_box.decrypt(nacl.encoding.HexEncoder.decode(encrypted_text))

    return plaintext.decode()


def is_allowed_url(url: str, url_filter: list) -> bool:
    """
    Takes an url, checks it against URL_FILTER and returns whether the url is allowed or not

    :param url: The url to test
    :param url_filter: The url filter

    :return: Whether the url is allowed or not
    """
    parsed_url = urlparse(url)
    for pattern in url_filter:
        if pattern == "*":
            return True

        if not url.startswith(pattern):
            continue

        parsed_pattern = urlparse(pattern)

        if parsed_url.scheme != parsed_pattern.scheme:
            # prevents https://good.corp being whitelisted and an attacker using http://good.corp
            continue

        if parsed_url.netloc != parsed_pattern.netloc:
            # prevents https://good.corp being whitelisted and an attacker using https://good.corp.evil.org
            continue

        if parsed_pattern.path and (not parsed_url.path or os.path.abspath(parsed_pattern.path).startswith(os.path.abspath(parsed_url.path))):
            # prevents path traversals with https://good.corp/allowed being whitelisted and an attacker using something like "https://good.corp/allowed/../protected"
            continue

        return True

    return False


def is_allowed_callback_url(url: str) -> bool:
    """
    Takes an url, checks it against ALLOWED_CALLBACK_URL_PREFIX and returns whether the url is allowed or not

    :param url: The url to test

    :return: Whether the url is allowed or not
    """

    return is_allowed_url(url, settings.ALLOWED_CALLBACK_URL_PREFIX)


def is_allowed_other_s3_endpoint_url(url: str) -> bool:
    """
    Takes an url, checks it against ALLOWED_OTHER_S3_ENDPOINT_URL_PREFIX and returns whether the url is allowed or not

    :param url: The url to test

    :return: Whether the url is allowed or not
    """

    return is_allowed_url(url, settings.ALLOWED_OTHER_S3_ENDPOINT_URL_PREFIX)


def create_user(username, password, email, gen_authkey=True, display_name=''):

    username = username.strip().lower()
    email = email.strip().lower().encode()

    email_bcrypt = bcrypt.hashpw(email, settings.EMAIL_SECRET_SALT.encode()).decode().replace(
        settings.EMAIL_SECRET_SALT, '', 1)

    if User.objects.filter(email_bcrypt=email_bcrypt).exists():
        return { 'error': 'USER_WITH_EMAIL_ALREADY_EXISTS' }

    if User.objects.filter(username=username).exists():
        return { 'error': 'USER_WITH_USERNAME_ALREADY_EXISTS' }

    user_sauce = binascii.hexlify(os.urandom(32))

    hashing_params = default_hashing_parameters()

    authkey_hashed = None
    if gen_authkey:
        authkey = generate_authkey(username, password, u=hashing_params['u'], r=hashing_params['r'], p=hashing_params['p'], l=hashing_params['l']).decode()
        authkey_hashed = make_password(authkey)

    box = PrivateKey.generate()
    public_key = box.public_key.encode(encoder=nacl.encoding.HexEncoder)
    private_key_decrypted = box.encode(encoder=nacl.encoding.HexEncoder)
    (private_key, private_key_nonce) = encrypt_secret(
        private_key_decrypted,
        password,
        user_sauce,
        u=hashing_params['u'],
        r=hashing_params['r'],
        p=hashing_params['p'],
        l=hashing_params['l'],
    )

    secret_key_decrypted = binascii.hexlify(os.urandom(32))
    (secret_key, secret_key_nonce) = encrypt_secret(
        secret_key_decrypted,
        password,
        user_sauce,
        u=hashing_params['u'],
        r=hashing_params['r'],
        p=hashing_params['p'],
        l=hashing_params['l'],
    )

    # normally encrypt emails, so they are not stored in plaintext with a random nonce
    db_secret_key = hashlib.sha256(settings.DB_SECRET.encode()).hexdigest()
    crypto_box = nacl.secret.SecretBox(db_secret_key, encoder=nacl.encoding.HexEncoder)
    encrypted_email = crypto_box.encrypt(email, nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
    email = nacl.encoding.HexEncoder.encode(encrypted_email)

    user = User.objects.create(
        username=username,
        display_name=display_name,
        email=email.decode(),
        email_bcrypt=email_bcrypt,
        authkey=authkey_hashed,
        public_key=public_key.decode(),
        private_key=private_key.decode(),
        private_key_nonce=private_key_nonce.decode(),
        secret_key=secret_key.decode(),
        secret_key_nonce=secret_key_nonce.decode(),
        is_email_active=True,
        is_active=True,
        user_sauce=user_sauce.decode(),
        credit=settings.SHARD_CREDIT_DEFAULT_NEW_USER,
    )

    return {
        'user': user,
        'private_key_decrypted': private_key_decrypted,
        'secret_key_decrypted': secret_key_decrypted,
    }

def filter_as_json(data, filter):
    """
    Takes any string and interprets it as nested json encoded objects which will be filtered by the filter array.
    The function will return a string with the filtered content

    :param data:
    :type data:
    :param filter:
    :type filter:
    :return:
    :rtype:
    """
    try:
        decrypted_data = json.loads(data)
    except TypeError:
        return ''

    for f in filter:
        try:
            decrypted_data = json.loads(decrypted_data)
        except TypeError:
            pass

        try:
            decrypted_data = decrypted_data[f]
            continue
        except KeyError:
            # Key is not present
            pass

        decrypted_data = ''
        break

    if isinstance(decrypted_data, str):
        return decrypted_data
    else:
        return json.dumps(decrypted_data)

def get_ip(request):
    """
    Analyzes a request and returns the ip of the client.

    :param request:
    :return:
    """
    if settings.TRUSTED_IP_HEADER and request.META.get(settings.TRUSTED_IP_HEADER, None):
        return request.META.get(settings.TRUSTED_IP_HEADER, None)
    else:
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        remote_addr = request.META.get('REMOTE_ADDR')
        num_proxies = settings.NUM_PROXIES

        if num_proxies is not None:
            if num_proxies == 0 or xff is None:
                return remote_addr
            addrs = xff.split(',')
            client_addr = addrs[-min(num_proxies, len(addrs))]
            return client_addr.strip()

        return remote_addr

def get_country(request):
    if settings.TRUSTED_COUNTRY_HEADER:
        return request.META.get(settings.TRUSTED_COUNTRY_HEADER, None)
    return None

def in_networks(ip_address, networks):
    """
    Takes an ip address and and array of networks, each in String representation.
    Will return whether the ip address in one of the network ranges

    :param ip_address:
    :type ip_address:
    :param networks:
    :type networks:
    :return:
    :rtype:
    """

    for network in networks:
        ip_network = ipaddress.ip_network(network)
        if ip_address in ip_network:
            return True

    return False

def get_uuid_start_and_end(count, position):
    """
    Divides 128 bit into count amount of chunks and returns the borders for the given position (smallest and biggest
    possible uuid)

    :param count:
    :type count:
    :param position:
    :type position:
    :return:
    :rtype:
    """
    max = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',16)

    start = UUID(int=int(position * float(max) / count))
    end = UUID(int=int((position + 1) * float(max) / count)-1)

    return start, end


def fileserver_access(cmsl, ip_address, read=None, write=None, allow_link_shares=None):
    """
    Tests weather an ip address has access for a specific cluster member shard link

    :param cmsl:
    :type cmsl:
    :param ip_address:
    :type ip_address:
    :param read:
    :type read:
    :param write:
    :type write:
    :return:
    :rtype:
    """

    if write:
        if not cmsl.write or not cmsl.member.write:
            return False

        ip_write_whitelist = json.loads(cmsl.ip_write_whitelist)
        ip_write_blacklist = json.loads(cmsl.ip_write_blacklist)

        has_write_whitelist = len(ip_write_whitelist) > 0
        write_blacklisted = in_networks(ip_address, ip_write_blacklist)
        write_whitelisted = in_networks(ip_address, ip_write_whitelist)
        if has_write_whitelist and not write_whitelisted:
            return False

        if write_blacklisted:
            return False

    if read:
        if not cmsl.read or not cmsl.member.read:
            return False

        ip_read_whitelist = json.loads(cmsl.ip_read_whitelist)
        ip_read_blacklist = json.loads(cmsl.ip_read_blacklist)

        has_read_whitelist = len(ip_read_whitelist) > 0
        read_blacklisted = in_networks(ip_address, ip_read_blacklist)
        read_whitelisted = in_networks(ip_address, ip_read_whitelist)
        if has_read_whitelist and not read_whitelisted:
            return False

        if read_blacklisted:
            return False

    return True
