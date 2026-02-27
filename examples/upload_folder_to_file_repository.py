"""
Uploads a local folder tree as Psono file entries to a file repository.

What this script does:
1. Logs in with an unrestricted API key
2. Reads the first password datastore
3. Creates (or reuses) a target folder in the datastore
4. Replicates the local subfolder structure inside that target folder
5. Uploads every file with the same mechanism used by psono-client for file repositories:
   - split into 128 MB chunks
   - encrypt each chunk with a random per-file secret key (nonce prepended)
   - hash each encrypted chunk with SHA-512
   - request a signed upload URL via /file-repository/upload/
   - upload encrypted bytes to the signed URL
6. Stores file metadata (file_id, file_chunks, file_secret_key, etc.) in the datastore
"""

import binascii
import hashlib
import json
import os
import socket
import uuid

import nacl.encoding
import nacl.secret
import nacl.signing
import nacl.utils
import requests
from nacl.public import Box, PrivateKey, PublicKey

api_key_id = "e1cd9c08-4887-4b06-a26d-c92b1e84f49e"
api_key_private_key = "0bbc18ac5d82ffabe324722ade66d99378c7772eef727e8e255e38ad2ab9f50c"
api_key_secret_key = "04ab9b23de0f710e2c521fb1fbb77802dbd9f1586c31fd454b0497f0aa94acb4"
server_url = "https://psonoclient.chickahoona.com/server"
server_public_key = "02da2ad857321d701d754a7e60d0a147cdbc400ff4465e1f57bc2d9fbfeddf0b"
server_signature = "4ce9e761e1d458fe18af577c50eb8249a0de535c9bd6b7a97885c331b46dcbd1"

SSL_VERIFY = False
FILE_CHUNK_SIZE = 128 * 1024 * 1024

# Script parameters
LOCAL_FOLDER_PATH = "./files"
TARGET_FOLDER_NAME = None  # None = use local folder name
FILE_REPOSITORY_ID = None  # None = use first writable repository


def get_device_description():
    return "File Repository Upload Script " + socket.gethostname()


def generate_client_login_info():
    box = PrivateKey.generate()
    session_private_key = box.encode(encoder=nacl.encoding.HexEncoder).decode()
    session_public_key = box.public_key.encode(
        encoder=nacl.encoding.HexEncoder
    ).decode()

    info = {
        "api_key_id": api_key_id,
        "session_public_key": session_public_key,
        "device_description": get_device_description(),
    }

    info = json.dumps(info)

    signing_box = nacl.signing.SigningKey(
        api_key_private_key, encoder=nacl.encoding.HexEncoder
    )
    signed = signing_box.sign(info.encode())
    signature = binascii.hexlify(signed.signature)

    return session_private_key, {"info": info, "signature": signature.decode()}


def decrypt_server_login_info(
    login_info_hex, login_info_nonce_hex, session_public_key, session_private_key
):
    crypto_box = Box(
        PrivateKey(session_private_key, encoder=nacl.encoding.HexEncoder),
        PublicKey(session_public_key, encoder=nacl.encoding.HexEncoder),
    )

    login_info = nacl.encoding.HexEncoder.decode(login_info_hex)
    login_info_nonce = nacl.encoding.HexEncoder.decode(login_info_nonce_hex)
    login_info = json.loads(crypto_box.decrypt(login_info, login_info_nonce).decode())

    return login_info


def verify_signature(login_info, login_info_signature):
    verify_key = nacl.signing.VerifyKey(
        server_signature, encoder=nacl.encoding.HexEncoder
    )
    verify_key.verify(login_info.encode(), binascii.unhexlify(login_info_signature))


def decrypt_symmetric(text_hex, nonce_hex, secret_hex):
    text = nacl.encoding.HexEncoder.decode(text_hex)
    nonce = nacl.encoding.HexEncoder.decode(nonce_hex)
    secret_box = nacl.secret.SecretBox(secret_hex, encoder=nacl.encoding.HexEncoder)
    return secret_box.decrypt(text, nonce)


def encrypt_symmetric(msg, secret_hex):
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    secret_box = nacl.secret.SecretBox(secret_hex, encoder=nacl.encoding.HexEncoder)
    encrypted = secret_box.encrypt(msg.encode(), nonce)
    text = encrypted[len(nonce) :]

    nonce_hex = nacl.encoding.HexEncoder.encode(nonce).decode()
    text_hex = nacl.encoding.HexEncoder.encode(text).decode()
    return {"text": text_hex, "nonce": nonce_hex}


def decrypt_with_api_secret_key(secret_hex, secret_nonce_hex):
    return decrypt_symmetric(secret_hex, secret_nonce_hex, api_key_secret_key)


def api_request(
    method,
    endpoint,
    data=None,
    token=None,
    transport_secret_key=None,
    auth_prefix="Token",
):
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = auth_prefix + " " + token

    payload = data
    if payload is not None and not isinstance(payload, str):
        payload = json.dumps(payload)

    if transport_secret_key and payload is not None:
        payload = json.dumps(encrypt_symmetric(payload, transport_secret_key))

    response = requests.request(
        method, server_url + endpoint, data=payload, headers=headers, verify=SSL_VERIFY
    )
    response.raise_for_status()
    response_json = response.json()

    if not transport_secret_key:
        return response_json

    decrypted_content = decrypt_symmetric(
        response_json["text"], response_json["nonce"], transport_secret_key
    )
    return json.loads(decrypted_content)


def api_login(client_login_info):
    return api_request("POST", "/api-key/login/", data=client_login_info)


def api_logout(token, session_secret_key):
    return api_request(
        "POST",
        "/authentication/logout/",
        token=token,
        transport_secret_key=session_secret_key,
    )


def api_read_datastores(token, session_secret_key):
    return api_request(
        "GET", "/datastore/", token=token, transport_secret_key=session_secret_key
    )


def api_read_datastore(token, session_secret_key, datastore_id):
    return api_request(
        "GET",
        "/datastore/" + datastore_id + "/",
        token=token,
        transport_secret_key=session_secret_key,
    )


def api_write_datastore(
    token, session_secret_key, datastore_id, encrypted_data, encrypted_data_nonce
):
    return api_request(
        "POST",
        "/datastore/",
        data={
            "datastore_id": datastore_id,
            "data": encrypted_data,
            "data_nonce": encrypted_data_nonce,
        },
        token=token,
        transport_secret_key=session_secret_key,
    )


def api_write_share(
    token, session_secret_key, share_id, encrypted_data, encrypted_data_nonce
):
    return api_request(
        "PUT",
        "/share/",
        data={
            "share_id": share_id,
            "data": encrypted_data,
            "data_nonce": encrypted_data_nonce,
        },
        token=token,
        transport_secret_key=session_secret_key,
    )


def api_read_share(token, session_secret_key, share_id):
    return api_request(
        "GET",
        "/share/" + share_id + "/",
        token=token,
        transport_secret_key=session_secret_key,
    )


def api_read_file_repositories(token, session_secret_key):
    return api_request(
        "GET", "/file-repository/", token=token, transport_secret_key=session_secret_key
    )


def api_create_file(
    token,
    session_secret_key,
    file_repository_id,
    size,
    chunk_count,
    link_id,
    parent_datastore_id=None,
    parent_share_id=None,
):
    payload = {
        "file_repository_id": file_repository_id,
        "size": size,
        "chunk_count": chunk_count,
        "link_id": link_id,
    }

    if parent_share_id:
        payload["parent_share_id"] = parent_share_id
    elif parent_datastore_id:
        payload["parent_datastore_id"] = parent_datastore_id

    return api_request(
        "PUT",
        "/file/",
        data=payload,
        token=token,
        transport_secret_key=session_secret_key,
    )


def api_file_repository_upload(
    file_transfer_id,
    file_transfer_secret_key,
    chunk_size,
    chunk_position,
    hash_checksum,
):
    return api_request(
        "PUT",
        "/file-repository/upload/",
        data={
            "chunk_size": chunk_size,
            "chunk_position": chunk_position,
            "hash_checksum": hash_checksum,
        },
        token=file_transfer_id,
        transport_secret_key=file_transfer_secret_key,
        auth_prefix="Filetransfer",
    )


def generate_secret_key_hex():
    return nacl.encoding.HexEncoder.encode(
        nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    ).decode()


def encrypt_file_chunk(plain_chunk, file_secret_key_hex):
    secret_box = nacl.secret.SecretBox(
        file_secret_key_hex, encoder=nacl.encoding.HexEncoder
    )
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = secret_box.encrypt(plain_chunk, nonce)
    return bytes(encrypted)


def upload_chunk_to_signed_url(file_repository_type, upload_ticket, encrypted_chunk):
    url = upload_ticket.get("url", "")
    fields = upload_ticket.get("fields", {})

    if file_repository_type in ["aws_s3", "backblaze", "other_s3", "do_spaces"]:
        response = requests.post(
            url,
            data=fields if isinstance(fields, dict) else {},
            files={"file": ("chunk", encrypted_chunk, "application/octet-stream")},
            verify=SSL_VERIFY,
        )
    elif file_repository_type == "gcp_cloud_storage":
        response = requests.put(
            url,
            data=encrypted_chunk,
            headers={"Content-Type": "application/octet-stream"},
            verify=SSL_VERIFY,
        )
    elif file_repository_type == "azure_blob":
        response = requests.put(
            url,
            data=encrypted_chunk,
            headers={"x-ms-blob-type": "BlockBlob"},
            verify=SSL_VERIFY,
        )
    else:
        raise Exception(
            "Unsupported file repository type: " + str(file_repository_type)
        )

    response.raise_for_status()


def find_folder_by_name(folder_name, folder_list):
    if not folder_list:
        return None
    for folder in folder_list:
        if folder.get("name") == folder_name:
            return folder
    return None


def create_folder_if_not_exist(folder_name, parent_folder):
    if "folders" not in parent_folder:
        parent_folder["folders"] = []

    existing_folder = find_folder_by_name(folder_name, parent_folder["folders"])
    if existing_folder:
        return existing_folder

    folder = {
        "id": str(uuid.uuid4()),
        "name": folder_name,
    }
    parent_folder["folders"].append(folder)
    return folder


def append_file_item(target_folder, file_item):
    if "items" not in target_folder:
        target_folder["items"] = []
    target_folder["items"].append(file_item)


def select_file_repository(file_repositories, requested_file_repository_id=None):
    writable_repositories = [
        repository
        for repository in file_repositories
        if repository.get("active")
        and repository.get("write")
        and repository.get("accepted")
    ]

    if requested_file_repository_id:
        for repository in writable_repositories:
            if repository.get("id") == requested_file_repository_id:
                return repository
        raise Exception(
            "Requested file repository not found or not writable: "
            + requested_file_repository_id
        )

    if len(writable_repositories) == 0:
        raise Exception("No writable file repository available for this user")

    return writable_repositories[0]


def upload_file_to_repository(
    token,
    session_secret_key,
    file_repository,
    parent_context,
    target_folder,
    local_file_path,
    relative_file_path,
):
    file_name = os.path.basename(local_file_path)
    plain_file_size = os.path.getsize(local_file_path)
    chunk_count = (
        (plain_file_size + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE
        if plain_file_size > 0
        else 0
    )
    storage_size = plain_file_size + chunk_count * 40
    link_id = str(uuid.uuid4())
    file_secret_key = generate_secret_key_hex()

    create_result = api_create_file(
        token=token,
        session_secret_key=session_secret_key,
        file_repository_id=file_repository["id"],
        size=storage_size,
        chunk_count=chunk_count,
        link_id=link_id,
        parent_datastore_id=parent_context.get("parent_datastore_id"),
        parent_share_id=parent_context.get("parent_share_id"),
    )

    file_id = create_result["file_id"]
    file_transfer_id = create_result["file_transfer_id"]
    file_transfer_secret_key = create_result["file_transfer_secret_key"]

    chunks = {}

    if chunk_count > 0:
        with open(local_file_path, "rb") as file_handle:
            chunk_position = 1
            while True:
                plain_chunk = file_handle.read(FILE_CHUNK_SIZE)
                if len(plain_chunk) == 0:
                    break

                encrypted_chunk = encrypt_file_chunk(plain_chunk, file_secret_key)
                hash_checksum = hashlib.sha512(encrypted_chunk).hexdigest()

                upload_ticket = api_file_repository_upload(
                    file_transfer_id=file_transfer_id,
                    file_transfer_secret_key=file_transfer_secret_key,
                    chunk_size=len(plain_chunk),
                    chunk_position=chunk_position,
                    hash_checksum=hash_checksum,
                )

                upload_chunk_to_signed_url(
                    file_repository["type"], upload_ticket, encrypted_chunk
                )

                chunks[chunk_position] = hash_checksum
                print(
                    "  uploaded chunk",
                    str(chunk_position) + "/" + str(chunk_count),
                    "for",
                    relative_file_path,
                )
                chunk_position += 1

    file_item = {
        "id": link_id,
        "name": file_name,
        "type": "file",
        "file_title": file_name,
        "file_id": file_id,
        "file_secret_key": file_secret_key,
        "file_size": plain_file_size,
        "file_repository_id": file_repository["id"],
        "file_chunks": chunks,
    }

    append_file_item(target_folder, file_item)


def main():
    local_folder_path = os.path.abspath(LOCAL_FOLDER_PATH)
    if not os.path.isdir(local_folder_path):
        print("ERROR: local folder does not exist:", local_folder_path)
        return

    target_folder_name = TARGET_FOLDER_NAME or os.path.basename(
        local_folder_path.rstrip(os.sep)
    )

    session_private_key, client_login_info = generate_client_login_info()
    json_response = api_login(client_login_info)

    verify_signature(json_response["login_info"], json_response["login_info_signature"])
    decrypted_server_login_info = decrypt_server_login_info(
        json_response["login_info"],
        json_response["login_info_nonce"],
        json_response["server_session_public_key"],
        session_private_key,
    )

    token = decrypted_server_login_info["token"]
    session_secret_key = decrypted_server_login_info["session_secret_key"]

    if decrypted_server_login_info["api_key_restrict_to_secrets"]:
        print("ERROR: API key is restricted. This script requires unrestricted key.")
        return
    if not decrypted_server_login_info["api_key_read"]:
        print("ERROR: API key does not allow read.")
        return
    if not decrypted_server_login_info["api_key_write"]:
        print("ERROR: API key does not allow write.")
        return

    user_secret_key = decrypt_with_api_secret_key(
        decrypted_server_login_info["user"]["secret_key"],
        decrypted_server_login_info["user"]["secret_key_nonce"],
    )

    datastores = api_read_datastores(token, session_secret_key)

    datastore_id = None
    datastore_secret = None
    datastore_content = None
    for datastore in datastores["datastores"]:
        if datastore["type"] != "password":
            continue

        datastore_id = datastore["id"]
        datastore_read_result = api_read_datastore(
            token, session_secret_key, datastore_id
        )
        datastore_secret = decrypt_symmetric(
            datastore_read_result["secret_key"],
            datastore_read_result["secret_key_nonce"],
            user_secret_key,
        )
        datastore_content = json.loads(
            decrypt_symmetric(
                datastore_read_result["data"],
                datastore_read_result["data_nonce"],
                datastore_secret,
            )
        )
        break

    if datastore_id is None:
        print(
            "ERROR: No password datastore found. Please create one first in the web client."
        )
        return

    if not isinstance(datastore_content, dict):
        raise Exception("Invalid datastore content")

    file_repositories_result = api_read_file_repositories(token, session_secret_key)
    file_repository = select_file_repository(
        file_repositories_result.get("file_repositories", []), FILE_REPOSITORY_ID
    )

    print(
        "Using file repository:",
        file_repository["id"],
        "(" + file_repository["type"] + ")",
    )
    print("Uploading local folder:", local_folder_path)
    print("Target datastore folder:", target_folder_name)

    root_target_folder = create_folder_if_not_exist(
        target_folder_name, datastore_content
    )

    share_states = {}

    def resolve_share_secret_key(share_id, folder_reference, parent_content):
        if folder_reference.get("share_secret_key"):
            return folder_reference["share_secret_key"]

        share_index = (
            parent_content.get("share_index", {})
            if isinstance(parent_content, dict)
            else {}
        )
        if share_id in share_index and share_index[share_id].get("secret_key"):
            return share_index[share_id].get("secret_key")

        datastore_share_index = datastore_content.get("share_index", {})
        if share_id in datastore_share_index and datastore_share_index[share_id].get(
            "secret_key"
        ):
            return datastore_share_index[share_id].get("secret_key")

        return None

    def get_share_state(share_id, share_secret_key):
        if share_id in share_states:
            return share_states[share_id]

        share_read_result = api_read_share(token, session_secret_key, share_id)
        share_content = json.loads(
            decrypt_symmetric(
                share_read_result["data"],
                share_read_result["data_nonce"],
                share_secret_key,
            )
        )

        share_states[share_id] = {
            "secret_key": share_secret_key,
            "content": share_content,
            "dirty": False,
        }
        return share_states[share_id]

    def enter_folder(
        folder_reference, parent_content, current_parent_context, current_owner
    ):
        share_id = folder_reference.get("share_id")
        if share_id:
            share_secret_key = resolve_share_secret_key(
                share_id, folder_reference, parent_content
            )
            if not share_secret_key:
                raise Exception("Unable to resolve secret key for share: " + share_id)

            share_state = get_share_state(share_id, share_secret_key)
            return (
                share_state["content"],
                {"parent_share_id": share_id, "parent_datastore_id": None},
                ("share", share_id),
            )

        return (folder_reference, current_parent_context, current_owner)

    root_folder_content, root_parent_context, root_owner = enter_folder(
        root_target_folder,
        datastore_content,
        {"parent_share_id": None, "parent_datastore_id": datastore_id},
        ("datastore", None),
    )

    uploaded_files = 0
    for dirpath, dirnames, filenames in os.walk(local_folder_path):
        dirnames.sort()
        filenames.sort()

        relative_dir = os.path.relpath(dirpath, local_folder_path)
        target_folder = root_folder_content
        parent_context = root_parent_context
        folder_owner = root_owner

        if relative_dir and relative_dir != ".":
            for part in relative_dir.split(os.sep):
                if not part:
                    continue

                if not isinstance(target_folder, dict):
                    raise Exception(
                        "Invalid folder structure while traversing target path"
                    )

                existing_folder = find_folder_by_name(
                    part, target_folder.get("folders", [])
                )
                if existing_folder is None:
                    existing_folder = create_folder_if_not_exist(part, target_folder)
                    if folder_owner[0] == "share":
                        share_states[folder_owner[1]]["dirty"] = True

                target_folder, parent_context, folder_owner = enter_folder(
                    existing_folder,
                    target_folder,
                    parent_context,
                    folder_owner,
                )

        for filename in filenames:
            local_file_path = os.path.join(dirpath, filename)
            if not os.path.isfile(local_file_path):
                continue

            relative_file_path = os.path.relpath(local_file_path, local_folder_path)
            print("Uploading:", relative_file_path)

            upload_file_to_repository(
                token=token,
                session_secret_key=session_secret_key,
                file_repository=file_repository,
                parent_context=parent_context,
                target_folder=target_folder,
                local_file_path=local_file_path,
                relative_file_path=relative_file_path,
            )
            uploaded_files += 1

            if folder_owner[0] == "share":
                share_states[folder_owner[1]]["dirty"] = True

    for share_id, share_state in share_states.items():
        if not share_state["dirty"]:
            continue

        encrypted_share = encrypt_symmetric(
            json.dumps(share_state["content"]), share_state["secret_key"]
        )
        api_write_share(
            token,
            session_secret_key,
            share_id,
            encrypted_share["text"],
            encrypted_share["nonce"],
        )

    encrypted_datastore = encrypt_symmetric(
        json.dumps(datastore_content), datastore_secret
    )
    api_write_datastore(
        token,
        session_secret_key,
        datastore_id,
        encrypted_datastore["text"],
        encrypted_datastore["nonce"],
    )

    api_logout(token, session_secret_key)

    print("Done. Uploaded", uploaded_files, "files into folder", target_folder_name)


if __name__ == "__main__":
    main()
