from .s3 import s3_construct_signed_download_url, s3_construct_signed_upload_url, s3_delete, create_key as _create_key

def backblaze_construct_signed_upload_url(bucket, region, access_key_id, secret_access_key, hash_checksum):
    """
    Constructs the signed upload url

    :param bucket: The target bucket
    :type bucket:
    :param region: The target region
    :type region:
    :param access_key_id: The s3 access key ID
    :type access_key_id:
    :param secret_access_key: The s3 secret access key
    :type secret_access_key:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:

    :return:
    :rtype:
    """

    return s3_construct_signed_upload_url(bucket, region, access_key_id, secret_access_key, hash_checksum, endpoint_url='https://s3.' + region + '.backblazeb2.com')


def backblaze_construct_signed_download_url(bucket, region, access_key_id, secret_access_key, hash_checksum):
    """
    Constructs the signed upload url

    :param bucket: The target bucket
    :type bucket:
    :param region: The target region
    :type region:
    :param access_key_id: The s3 access key ID
    :type access_key_id:
    :param secret_access_key: The s3 secret access key
    :type secret_access_key:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:

    :return:
    :rtype:
    """

    return s3_construct_signed_download_url(bucket, region, access_key_id, secret_access_key, hash_checksum, endpoint_url='https://s3.' + region + '.backblazeb2.com')


def backblaze_delete(bucket, region, access_key_id, secret_access_key, hash_checksum):
    """
    Deletes an object from s3

    :param bucket: The target bucket
    :type bucket:
    :param region: The target region
    :type region:
    :param access_key_id: The s3 access key ID
    :type access_key_id:
    :param secret_access_key: The s3 secret access key
    :type secret_access_key:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:

    :return:
    :rtype:
    """
    return s3_delete(bucket, region, access_key_id, secret_access_key, hash_checksum, endpoint_url='https://s3.' + region + '.backblazeb2.com')


def create_key(hash_checksum):
    """
    Takes the hash checksum and returns the path on the server

    :param hash_checksum:
    :type hash_checksum:

    :return:
    :rtype:
    """

    return _create_key(hash_checksum=hash_checksum)