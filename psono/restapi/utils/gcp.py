import json
import base64
import time
import datetime

import Cryptodome.Hash.SHA256 as SHA256
from Cryptodome.PublicKey import RSA
import Cryptodome.Signature.PKCS1_v1_5 as PKCS1_v1_5
import requests

def gcs_construct_signed_upload_url(bucket, json_key, hash_checksum):
    """
    Constructs the signed upload url

    :param bucket: The target bucket
    :type bucket:
    :param json_key: The json encoded config object
    :type json_key:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:

    :return:
    :rtype:
    """

    method = 'PUT'
    content_type = 'application/octet-stream'
    md5_digest = ''

    return construct_signed_url(bucket, json_key, hash_checksum, method, content_type, md5_digest)


def gcs_construct_signed_download_url(bucket, json_key, hash_checksum):
    """
    Constructs the signed upload url

    :param bucket: The target bucket
    :type bucket:
    :param json_key: The json encoded config object
    :type json_key:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:

    :return:
    :rtype:
    """

    method = 'GET'

    return construct_signed_url(bucket, json_key, hash_checksum, method)


def gcs_construct_signed_delete_url(bucket, json_key, hash_checksum):
    """
    Constructs the signed delete url

    :param bucket: The target bucket
    :type bucket:
    :param json_key: The json encoded config object
    :type json_key:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:

    :return:
    :rtype:
    """

    method = 'DELETE'

    return construct_signed_url(bucket, json_key, hash_checksum, method)


def construct_signed_url(bucket, json_key, hash_checksum, method, content_type='', md5_digest=''):
    """
    Constructs the signed url

    :param bucket: The target bucket
    :type bucket:
    :param json_key: The json encoded config object
    :type json_key:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:
    :param method:
    :type method:
    :param content_type:
    :type content_type:
    :param md5_digest:
    :type md5_digest:

    :return:
    :rtype:
    """

    # Parse config string
    json_config = json.loads(json_key)

    # Create parameters
    client_id_email = json_config['client_email']
    key = RSA.importKey(json_config['private_key'])
    path = create_file_repository_path(bucket, hash_checksum)

    # create the url as base url and params
    base_url, query_params = create_url(client_id_email, key, method, path, content_type, md5_digest)

    return base_url, query_params


def create_file_repository_path(bucket, hash_checksum):
    """
    Takes the bucket and the hash checksum and returns the path on the server

    :param bucket:
    :type bucket:
    :param hash_checksum:
    :type hash_checksum:

    :return:
    :rtype:
    """

    return '/' + bucket + '/' + hash_checksum[0:2] + '/' + hash_checksum[2:4] + '/' + hash_checksum[4:6] + '/' + hash_checksum[6:8] + '/' + hash_checksum


def base64_sign(key, plaintext):
    """
    Signs and returns a base64-encoded SHA256 digest.

    :param key:
    :type key:
    :param plaintext:
    :type plaintext:

    :return:
    :rtype:
    """

    shahash = SHA256.new(plaintext.encode())
    signer = PKCS1_v1_5.new(key)
    signature_bytes = signer.sign(shahash)

    return base64.b64encode(signature_bytes).decode()


def create_signature_string(method, path, content_md5, content_type, expiration):
    """
    Creates the signature for signed urls

    :param method:
    :type method:
    :param path:
    :type path:
    :param content_md5:
    :type content_md5:
    :param content_type:
    :type content_type:
    :param expiration:
    :type expiration:

    :return:
    :rtype:
    """

    signature_string = ('{method}\n'
                        '{content_md5}\n'
                        '{content_type}\n'
                        '{expiration}\n'
                        '{resource}')

    return signature_string.format(method=method,
                                   content_md5=content_md5,
                                   content_type=content_type,
                                   expiration=expiration,
                                   resource=path)


def create_url(client_id_email, key, method, path, content_type='', content_md5=''):
    """
    Creates a signed url for GCP storage

    :param client_id_email:
    :type client_id_email:
    :param key:
    :type key:
    :param method:
    :type method:
    :param path:
    :type path:
    :param content_type:
    :type content_type:
    :param content_md5:
    :type content_md5:

    :return:
    :rtype:
    """

    base_url = 'https://storage.googleapis.com' + path

    expiration = datetime.datetime.now() + datetime.timedelta(hours=1)
    expiration = int(time.mktime(expiration.timetuple()))

    signature_string = create_signature_string(method, path, content_md5,
                                                 content_type, expiration)
    signature_signed = base64_sign(key, signature_string)

    query_params = {'GoogleAccessId': client_id_email,
                    'Expires': str(expiration),
                    'Signature': signature_signed}

    return base_url, query_params


def gcs_download(bucket, json_key, hash_checksum):
    """
    Downloads a file with a GET request

    :param bucket:
    :type bucket:
    :param json_key:
    :type json_key:
    :param hash_checksum:
    :type hash_checksum:

    :return:
    :rtype:
    """

    base_url, query_params = gcs_construct_signed_download_url(bucket, json_key, hash_checksum)

    return requests.get(base_url, params=query_params)


def gcs_upload(bucket, json_key, hash_checksum, data):
    """
    Uploads a file with a PUT request

    :param bucket:
    :type bucket:
    :param json_key:
    :type json_key:
    :param hash_checksum:
    :type hash_checksum:
    :param data:
    :type data:

    :return:
    :rtype:
    """

    base_url, query_params = gcs_construct_signed_upload_url(bucket, json_key, hash_checksum)
    headers = {}
    headers['Content-Type'] = 'application/octet-stream'

    return requests.put(base_url, params=query_params, headers=headers, data=data)


def gcs_delete(bucket, json_key, hash_checksum):
    """
    Deletes a file with a DELETE request

    :param bucket:
    :type bucket:
    :param json_key:
    :type json_key:
    :param hash_checksum:
    :type hash_checksum:

    :return:
    :rtype:
    """

    base_url, query_params = gcs_construct_signed_delete_url(bucket, json_key, hash_checksum)

    return requests.delete(base_url, params=query_params)

