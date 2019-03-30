import boto3

def aws_construct_signed_upload_url(bucket, region, access_key_id, secret_access_key, hash_checksum):
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

    client = boto3.client(
        's3',
        region_name=region,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key
    )

    key = create_key(hash_checksum)

    url = client.generate_presigned_post(Bucket=bucket, Key=key, ExpiresIn=3600)

    return url


def aws_construct_signed_download_url(bucket, region, access_key_id, secret_access_key, hash_checksum):
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

    client = boto3.client(
        's3',
        region_name=region,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key
    )

    key = create_key(hash_checksum)

    url = client.generate_presigned_url(ClientMethod='get_object', Params={'Bucket': bucket, 'Key': key}, ExpiresIn=3600)

    return url


def aws_delete(bucket, region, access_key_id, secret_access_key, hash_checksum):
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

    client = boto3.client(
        's3',
        region_name=region,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key
    )

    key = create_key(hash_checksum)

    return client.delete_object(Bucket=bucket, Key=key)


def create_key(hash_checksum):
    """
    Takes the hash checksum and returns the path on the server

    :param hash_checksum:
    :type hash_checksum:

    :return:
    :rtype:
    """

    return hash_checksum[0:2] + '/' + hash_checksum[2:4] + '/' + hash_checksum[4:6] + '/' + hash_checksum[6:8] + '/' + hash_checksum