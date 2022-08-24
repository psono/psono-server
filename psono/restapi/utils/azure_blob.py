from azure.storage.blob import BlobSasPermissions, generate_blob_sas
from datetime import datetime, timedelta
import requests

def create_key(hash_checksum):
    """
    Takes the hash checksum and returns the path on the server

    :param hash_checksum:
    :type hash_checksum:

    :return:
    :rtype:
    """

    return hash_checksum[0:2] + '/' + hash_checksum[2:4] + '/' + hash_checksum[4:6] + '/' + hash_checksum[6:8] + '/' + hash_checksum


def azure_blob_construct_signed_url(storage_account_name, storage_account_primary_key, container_name, hash_checksum, permission):
    """
    Constructs the signed url

    :param storage_account_name: The name of the storage account. The leading part before blob.core.windows.net
    :type storage_account_name: str
    :param storage_account_primary_key: The primary (or secondary) key shown under access keys of the storage account
    :type storage_account_primary_key: str
    :param container_name: The container name
    :type container_name: str
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum: str
    :param permission: The permission
    :type permission: azure.storage.blob.BlobSasPermissions

    :return: The signed upload url
    :rtype:
    """

    expiry = datetime.utcnow() + timedelta(hours=1)
    blob_name = create_key(hash_checksum)

    sas_token = generate_blob_sas(
        account_name=storage_account_name,
        container_name=container_name,
        blob_name=blob_name,
        account_key=storage_account_primary_key,
        permission=permission,
        expiry=expiry,
    )

    return f'https://{storage_account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_token}'


def azure_blob_construct_signed_upload_url(storage_account_name, storage_account_primary_key, container_name, hash_checksum):
    """
    Constructs the signed upload url

    :param storage_account_name: The name of the storage account. The leading part before blob.core.windows.net
    :type storage_account_name: str
    :param storage_account_primary_key: The primary (or secondary) key shown under access keys of the storage account
    :type storage_account_primary_key: str
    :param container_name: The container name
    :type container_name: str
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum: str

    :return: The signed upload url
    :rtype:
    """

    return azure_blob_construct_signed_url(storage_account_name, storage_account_primary_key, container_name, hash_checksum, BlobSasPermissions(write=True))


def azure_blob_construct_signed_download_url(storage_account_name, storage_account_primary_key, container_name, hash_checksum):
    """
    Constructs the signed download url

    :param storage_account_name: The name of the storage account. The leading part before blob.core.windows.net
    :type storage_account_name:
    :param storage_account_primary_key: The primary (or secondary) key shown under access keys of the storage account
    :type storage_account_primary_key:
    :param container_name: The container name
    :type container_name:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:

    :return: The signed upload url
    :rtype:
    """

    return azure_blob_construct_signed_url(storage_account_name, storage_account_primary_key, container_name, hash_checksum, BlobSasPermissions(read=True))


def azure_blob_construct_signed_delete_url(storage_account_name, storage_account_primary_key, container_name, hash_checksum):
    """
    Constructs the signed delete url

    :param storage_account_name: The name of the storage account. The leading part before blob.core.windows.net
    :type storage_account_name:
    :param storage_account_primary_key: The primary (or secondary) key shown under access keys of the storage account
    :type storage_account_primary_key:
    :param container_name: The container name
    :type container_name:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:

    :return: The signed delete url
    :rtype:
    """

    return azure_blob_construct_signed_url(storage_account_name, storage_account_primary_key, container_name, hash_checksum, BlobSasPermissions(delete=True))


def azure_blob_delete(storage_account_name, storage_account_primary_key, container_name, hash_checksum):
    """
    Deletes an azure blob including all snapshits

    :param storage_account_name: The name of the storage account. The leading part before blob.core.windows.net
    :type storage_account_name:
    :param storage_account_primary_key: The primary (or secondary) key shown under access keys of the storage account
    :type storage_account_primary_key:
    :param container_name: The container name
    :type container_name:
    :param hash_checksum: The sha512 checksum of the file
    :type hash_checksum:

    :return: The signed delete url
    :rtype:
    """
    delete_url = azure_blob_construct_signed_delete_url(storage_account_name, storage_account_primary_key, container_name, hash_checksum)

    return requests.delete(
        delete_url,
        headers={
            'x-ms-delete-snapshots': 'include',
        }
    )
