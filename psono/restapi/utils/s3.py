import boto3
from django.core.validators import RegexValidator


# Match the SDK's bucket-name character/length envelope, including legacy S3
# names (uppercase, underscores, up to 255 characters). Exclude dot-only path
# segments, but leave provider naming policy to storage.
validate_s3_bucket_name = RegexValidator(
    regex=r"\A(?!\.{1,2}\Z)[A-Za-z0-9._-]{1,255}\Z",
    message="BUCKET_IS_INVALID",
)

# Botocore permits mixed-case host labels, including for custom S3 regions.
validate_s3_region = RegexValidator(
    regex=r"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z",
    message="REGION_IS_INVALID",
)


def s3_construct_signed_upload_url(
    bucket,
    region,
    access_key_id,
    secret_access_key,
    hash_checksum,
    chunk_size,
    endpoint_url=None,
):
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
    :param chunk_size: The recorded size of the chunk in bytes
    :type chunk_size: int

    :return:
    :rtype:
    """

    validate_s3_bucket_name(bucket)
    validate_s3_region(region)

    client = boto3.client(
        "s3",
        region_name=region,
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
    )

    key = create_key(hash_checksum)

    # Older browser clients report the plaintext chunk size, but upload a chunk
    # with 40 additional bytes for the encryption nonce and authentication tag.
    # Allow that overhead until all clients report the encrypted chunk size.
    url = client.generate_presigned_post(
        Bucket=bucket,
        Key=key,
        Conditions=[["content-length-range", chunk_size, chunk_size + 40]],
        ExpiresIn=3600,
    )

    return url


def s3_construct_signed_download_url(
    bucket, region, access_key_id, secret_access_key, hash_checksum, endpoint_url=None
):
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

    validate_s3_bucket_name(bucket)
    validate_s3_region(region)

    client = boto3.client(
        "s3",
        region_name=region,
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
    )

    key = create_key(hash_checksum)

    url = client.generate_presigned_url(
        ClientMethod="get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=3600
    )

    return url


def s3_delete(
    bucket, region, access_key_id, secret_access_key, hash_checksum, endpoint_url=None
):
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
    :param endpoint_url: The endpoint URL, defautls to AWS if not specified
    :type hash_checksum:

    :return:
    :rtype:
    """

    validate_s3_bucket_name(bucket)
    validate_s3_region(region)

    client = boto3.client(
        "s3",
        region_name=region,
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
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

    return (
        hash_checksum[0:2]
        + "/"
        + hash_checksum[2:4]
        + "/"
        + hash_checksum[4:6]
        + "/"
        + hash_checksum[6:8]
        + "/"
        + hash_checksum
    )
