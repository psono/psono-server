"""
A small demo script that shows how to import Keepass data into the datastore.
"""

import uuid
import requests
import json
import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
import binascii
import socket
import os
import hashlib
from pykeepass import PyKeePass
import math

keepass_database_path = "/path/to/import.kdbx"
keepass_database_password = "save_and_secure_password"

api_key_id = ""
api_key_private_key = ""
api_key_secret_key = ""
server_url = "https://psono-server/server"
server_public_key = ""
server_signature = ""
fileserver_url = "https://psono-server/fileserver"
fileserver_shard_id = ""

SSL_VERIFY = True
FILE_CHUNK_SIZE = 128 * 1024 * 1024


def get_device_description():
    """
    This info is later shown in the "Open sessions" overview in the client.
    """
    return "Keepass Import Script " + socket.gethostname()


def generate_client_login_info():
    """
    Generates and signs the login info
    Returns a tuple of the session private key and the login info
    """
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

    # The first 128 chars (512 bits or 64 bytes) are the actual signature, the rest the binary encoded info
    signed = signing_box.sign(info.encode())
    signature = binascii.hexlify(signed.signature)

    return session_private_key, {
        "info": info,
        "signature": signature.decode(),
    }


def decrypt_server_login_info(
    login_info_hex, login_info_nonce_hex, session_public_key, session_private_key
):
    """
    Decrypts the server login info
    """
    crypto_box = Box(
        PrivateKey(session_private_key, encoder=nacl.encoding.HexEncoder),
        PublicKey(session_public_key, encoder=nacl.encoding.HexEncoder),
    )

    login_info = nacl.encoding.HexEncoder.decode(login_info_hex)
    login_info_nonce = nacl.encoding.HexEncoder.decode(login_info_nonce_hex)

    login_info = json.loads(crypto_box.decrypt(login_info, login_info_nonce).decode())

    return login_info


def verify_signature(login_info, login_info_signature):
    """
    Validates the server signature
    """
    verify_key = nacl.signing.VerifyKey(
        server_signature, encoder=nacl.encoding.HexEncoder
    )
    verify_key.verify(login_info.encode(), binascii.unhexlify(login_info_signature))


def decrypt_symmetric(text_hex, nonce_hex, secret):
    """
    Decrypts an encrypted text with nonce with the given secret
    """
    text = nacl.encoding.HexEncoder.decode(text_hex)
    nonce = nacl.encoding.HexEncoder.decode(nonce_hex)

    secret_box = nacl.secret.SecretBox(secret, encoder=nacl.encoding.HexEncoder)

    return secret_box.decrypt(text, nonce)


def encrypt_symmetric(msg, secret):
    """
    Encrypts a message with a random nonce and a given secret
    """
    # generate random nonce
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    # open crypto box with session secret
    secret_box = nacl.secret.SecretBox(secret, encoder=nacl.encoding.HexEncoder)

    # encrypt msg with crypto box and nonce
    encrypted = secret_box.encrypt(msg.encode(), nonce)

    # cut away the nonce
    text = encrypted[len(nonce) :]

    # convert nonce and encrypted msg to hex
    nonce_hex = nacl.encoding.HexEncoder.encode(nonce).decode()
    text_hex = nacl.encoding.HexEncoder.encode(text).decode()

    return {"text": text_hex, "nonce": nonce_hex}


def decrypt_with_api_secret_key(secret_hex, secret_nonce_hex):
    """
    Decrypts anything that is encrypted with the api keys secret
    """
    return decrypt_symmetric(secret_hex, secret_nonce_hex, api_key_secret_key)


def api_request(method, endpoint, data=None, token=None, session_secret_key=None):

    if token:
        headers = {
            "content-type": "application/json",
            "authorization": "Token " + token,
        }
    else:
        headers = {"content-type": "application/json"}

    if session_secret_key and data:
        data = json.dumps(encrypt_symmetric(data, session_secret_key))

    r = requests.request(
        method, server_url + endpoint, data=data, headers=headers, verify=SSL_VERIFY
    )

    if not session_secret_key:
        return r.json()
    else:
        encrypted_content = r.json()
        decrypted_content = decrypt_symmetric(
            encrypted_content["text"], encrypted_content["nonce"], session_secret_key
        )
        return json.loads(decrypted_content)


def api_login(client_login_info):
    """
    API Request: Sends the actual login
    """
    method = "POST"
    endpoint = "/api-key/login/"
    data = json.dumps(client_login_info)

    return api_request(method, endpoint, data)


def api_read_datastores(token, session_secret_key):
    """
    Reads all datastores
    """
    method = "GET"
    endpoint = "/datastore/"

    return api_request(
        method, endpoint, token=token, session_secret_key=session_secret_key
    )


def api_logout(token, session_secret_key):
    """
    Destroys the session
    """
    method = "POST"
    endpoint = "/authentication/logout/"

    return api_request(
        method, endpoint, token=token, session_secret_key=session_secret_key
    )


def api_read_datastore(token, session_secret_key, datastore_id):
    """
    Reads the content of a specific datastore
    """
    method = "GET"
    endpoint = "/datastore/" + datastore_id + "/"

    return api_request(
        method, endpoint, token=token, session_secret_key=session_secret_key
    )


def api_write_datastore(
    token, session_secret_key, datastore_id, encrypted_data, encrypted_data_nonce
):
    """
    Updates a datastore
    """
    method = "POST"
    endpoint = "/datastore/"
    data = json.dumps(
        {
            "datastore_id": datastore_id,
            "data": encrypted_data,
            "data_nonce": encrypted_data_nonce,
        }
    )

    return api_request(
        method, endpoint, data=data, token=token, session_secret_key=session_secret_key
    )


def api_write_share(
    token, session_secret_key, share_id, encrypted_data, encrypted_data_nonce
):
    """
    Updates a share
    """
    method = "PUT"
    endpoint = "/share/"
    data = json.dumps(
        {
            "share_id": share_id,
            "data": encrypted_data,
            "data_nonce": encrypted_data_nonce,
        }
    )

    return api_request(
        method, endpoint, data=data, token=token, session_secret_key=session_secret_key
    )


def api_create_share(
    token,
    session_secret_key,
    encrypted_data,
    encrypted_data_nonce,
    encrypted_key,
    encrypted_key_nonce,
    parent_datastore_id,
    link_id,
):
    """
    Creates a new share
    """
    method = "POST"
    endpoint = "/share/"
    data = json.dumps(
        {
            "data": encrypted_data,
            "data_nonce": encrypted_data_nonce,
            "key": encrypted_key,
            "key_nonce": encrypted_key_nonce,
            "key_type": "symmetric",
            "parent_datastore_id": parent_datastore_id,
            "link_id": link_id,
        }
    )

    return api_request(
        method, endpoint, data=data, token=token, session_secret_key=session_secret_key
    )


def api_create_share_right(
    token,
    session_secret_key,
    share_id,
    user_id,
    encrypted_key,
    encrypted_key_nonce,
    encrypted_title,
    encrypted_title_nonce,
    encrypted_type,
    encrypted_type_nonce,
):
    """
    Creates a user share right for a share
    """
    method = "PUT"
    endpoint = "/share/right/"
    data = json.dumps(
        {
            "share_id": share_id,
            "user_id": user_id,
            "key": encrypted_key,
            "key_nonce": encrypted_key_nonce,
            "title": encrypted_title,
            "title_nonce": encrypted_title_nonce,
            "type": encrypted_type,
            "type_nonce": encrypted_type_nonce,
            "read": True,
            "write": True,
            "grant": True,
        }
    )

    return api_request(
        method, endpoint, data=data, token=token, session_secret_key=session_secret_key
    )


def api_user_search(token, session_secret_key, user_username):
    """
    Searches users by username
    """
    method = "POST"
    endpoint = "/user/search/"
    data = json.dumps({"user_username": user_username})

    return api_request(
        method, endpoint, data=data, token=token, session_secret_key=session_secret_key
    )


def api_create_secret(
    token,
    session_secret_key,
    encrypted_data,
    encrypted_data_nonce,
    link_id,
    parent_datastore_id=None,
    parent_share_id=None,
    callback_url="",
    callback_user="",
    callback_pass="",
):
    """
    Creates a secret
    """
    method = "PUT"
    endpoint = "/secret/"
    payload = {
        "data": encrypted_data,
        "data_nonce": encrypted_data_nonce,
        "link_id": link_id,
        "callback_url": callback_url,
        "callback_user": callback_user,
        "callback_pass": callback_pass,
    }

    if parent_share_id:
        payload["parent_share_id"] = parent_share_id
    elif parent_datastore_id:
        payload["parent_datastore_id"] = parent_datastore_id

    data = json.dumps(payload)

    return api_request(
        method, endpoint, data=data, token=token, session_secret_key=session_secret_key
    )


def api_create_file(
    token,
    session_secret_key,
    size,
    chunk_count,
    link_id,
    parent_datastore_id=None,
):
    payload = {
        "shard_id": fileserver_shard_id,
        "size": size,
        "chunk_count": chunk_count,
        "link_id": link_id,
    }

    if parent_datastore_id:
        payload["parent_datastore_id"] = parent_datastore_id

    return api_request(
        "PUT",
        "/file/",
        data=json.dumps(payload),
        token=token,
        session_secret_key=session_secret_key,
    )


def upload_chunk_to_signed_url(
    upload_ticket, encrypted_chunk, chunk_position, hash_checksum
):

    ticket_decrypted = {
        "hash_checksum": hash_checksum,
        "chunk_position": chunk_position,
    }
    ticket_encrypted = encrypt_symmetric(
        json.dumps(ticket_decrypted), upload_ticket.get("file_transfer_secret_key", "")
    )

    response = requests.post(
        fileserver_url + "/upload/",
        data={
            "file_transfer_id": upload_ticket.get("file_transfer_id", ""),
            "ticket": ticket_encrypted.get("text", ""),
            "ticket_nonce": ticket_encrypted.get("nonce", ""),
        },
        files={"chunk": ("blob", encrypted_chunk, "application/octet-stream")},
        verify=SSL_VERIFY,
    )

    response.raise_for_status()


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


def encrypt_asymmetric(msg, recipient_public_key, sender_private_key):
    """
    Encrypts a message for a recipient with sender private key and random nonce
    """
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    crypto_box = Box(
        PrivateKey(sender_private_key, encoder=nacl.encoding.HexEncoder),
        PublicKey(recipient_public_key, encoder=nacl.encoding.HexEncoder),
    )

    encrypted = crypto_box.encrypt(msg.encode(), nonce)
    text = encrypted[len(nonce) :]

    nonce_hex = nacl.encoding.HexEncoder.encode(nonce).decode()
    text_hex = nacl.encoding.HexEncoder.encode(text).decode()

    return {"text": text_hex, "nonce": nonce_hex}


def encrypt_file_chunk(plain_chunk, file_secret_key_hex):
    secret_box = nacl.secret.SecretBox(
        file_secret_key_hex, encoder=nacl.encoding.HexEncoder
    )
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = secret_box.encrypt(plain_chunk, nonce)
    return bytes(encrypted)


def get_user_by_exact_username(token, session_secret_key, username):
    """
    Returns a user object for exact username match, otherwise None
    """
    try:
        result = api_user_search(token, session_secret_key, username)
    except Exception:
        return None

    users = result if isinstance(result, list) else [result]
    expected_username = username.strip().lower()

    for user in users:
        if not isinstance(user, dict):
            continue
        found_username = str(user.get("username", "")).strip().lower()
        if found_username == expected_username:
            return user

    return None


def import_attachment(base_attachment, datastore_id, token, session_secret_key):

    link_id = str(uuid.uuid4())
    file_secret_key = os.urandom(32).hex()
    plain_file_size = len(base_attachment.data)
    chunk_count = math.ceil(plain_file_size / FILE_CHUNK_SIZE)
    storage_size = plain_file_size + chunk_count * 40

    create_result = api_create_file(
        token=token,
        session_secret_key=session_secret_key,
        size=storage_size,
        chunk_count=chunk_count,
        link_id=link_id,
        parent_datastore_id=datastore_id,
    )

    file_id = create_result["file_id"]
    file_transfer_id = create_result["file_transfer_id"]
    file_transfer_secret_key = create_result["file_transfer_secret_key"]

    attachment_data = base_attachment.data

    chunks = []

    if chunk_count > 0:
        chunk_position = 1

        while True:
            plain_chunk = attachment_data[:FILE_CHUNK_SIZE]
            attachment_data = attachment_data[FILE_CHUNK_SIZE:]

            if len(plain_chunk) == 0:
                break

            encrypted_chunk = encrypt_file_chunk(plain_chunk, file_secret_key)
            hash_checksum = hashlib.sha512(encrypted_chunk).hexdigest()

            upload_chunk_to_signed_url(
                create_result, encrypted_chunk, chunk_position, hash_checksum
            )

            chunks.append({"hash": hash_checksum, "position": chunk_position})
            print(
                "uploaded chunk",
                str(chunk_position) + "/" + str(chunk_count),
                "for",
                base_attachment.filename,
            )

            chunk_position += 1

    return {
        "id": link_id,
        "file_id": file_id,
        "file_chunks": chunks,
        "file_secret_key": file_secret_key,
        "file_size": plain_file_size,
        "file_repository_id": None,
        "name": base_attachment.filename,
        "filename": base_attachment.filename,
        "file_shard_id": fileserver_shard_id,
    }


def import_entry(base_entry, datastore_id, token, session_secret_key):
    entry_item = {}

    if (base_entry.url or "") != "":
        entry_item = {
            "name": base_entry.title,
            "type": "website_password",
            "website_password_title": base_entry.title,
            "website_password_username": base_entry.username,
            "website_password_password": base_entry.password,
            "website_password_url": base_entry.url,
            "website_password_notes": base_entry.notes,
            "attachments": [],
        }
    else:
        entry_item = {
            "name": base_entry.title,
            "type": "application_password",
            "application_password_title": base_entry.title,
            "application_password_username": base_entry.username,
            "application_password_password": base_entry.password,
            "application_password_notes": base_entry.notes,
            "attachments": [],
        }

    for attachment in base_entry.attachments:
        entry_item["attachments"].append(
            import_attachment(attachment, datastore_id, token, session_secret_key)
        )

    secret_key = nacl.encoding.HexEncoder.encode(
        nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    ).decode()
    encrypted_secret = encrypt_symmetric(json.dumps(entry_item), secret_key)

    link_id = str(uuid.uuid4())

    create_secret_result = api_create_secret(
        token,
        session_secret_key,
        encrypted_secret["text"],
        encrypted_secret["nonce"],
        link_id,
        datastore_id,
        "",
        "",
        "",
    )

    obj_entry = {
        "id": link_id,
        "name": entry_item.get("name"),
        "type": entry_item.get("type"),
        "secret_id": create_secret_result.get("secret_id", ""),
        "secret_key": secret_key,
        "urlfilter": entry_item.get("website_password_url", ""),
    }

    return obj_entry


def import_group(base_group, datastore_id, token, session_secret_key):

    obj_group = {
        "id": str(uuid.uuid4()),
        "name": base_group.name,
        "folders": [],
        "items": [],
    }

    for group in base_group.subgroups:
        obj_group["folders"].append(
            import_group(group, datastore_id, token, session_secret_key)
        )

    for entry in base_group.entries:
        obj_group["items"].append(
            import_entry(entry, datastore_id, token, session_secret_key)
        )

    return obj_group


def import_kdbx_file(
    kdbx_file_path, kdbx_password, datastore_id, token, session_secret_key
):
    """
    Reads the KDBX file and returns the parsed data using pyKeePass
    """
    keepass = PyKeePass(kdbx_file_path, kdbx_password)

    return import_group(keepass.root_group, datastore_id, token, session_secret_key)


def main():
    # 1. Generate the login info including the private key for PFS
    session_private_key, client_login_info = generate_client_login_info()

    # 2. Send the login request and handle eventual exceptions, problems and so on ...
    json_response = api_login(client_login_info)

    # 3. Verify the signature in order to proof that we are really communicating with the server
    # (or someone who is in the posession of the servers private key :D)
    verify_signature(json_response["login_info"], json_response["login_info_signature"])

    # 4. Decrypt the actual login info with the token and session_secret_key for the transport encryption
    decrypted_sever_login_info = decrypt_server_login_info(
        json_response["login_info"],
        json_response["login_info_nonce"],
        json_response["server_session_public_key"],
        session_private_key,
    )

    token = decrypted_sever_login_info[
        "token"
    ]  # That is the token that we have to send always as header
    session_secret_key = decrypted_sever_login_info[
        "session_secret_key"
    ]  # that is the symmetric secret for the transport encryption
    user_username = decrypted_sever_login_info["user"]["username"]  # The username
    user_public_key = decrypted_sever_login_info["user"][
        "public_key"
    ]  # The user's public key

    if decrypted_sever_login_info["api_key_restrict_to_secrets"]:
        print("api key is restricted. it should only be used to read specific secrets")
        return
    if not decrypted_sever_login_info["api_key_read"]:
        print("api key doesn't allow read. Please allow read first")
        return

    if not decrypted_sever_login_info["api_key_write"]:
        print("api key doesn't allow write. Please allow write first")
        return

    # if the api key is unrestricted then the request will also return the encrypted secret and private key of the user, symmetric encrypted with the api secret key
    user_private_key = decrypt_with_api_secret_key(
        decrypted_sever_login_info["user"]["private_key"],
        decrypted_sever_login_info["user"]["private_key_nonce"],
    )  # The user's private key
    user_secret_key = decrypt_with_api_secret_key(
        decrypted_sever_login_info["user"]["secret_key"],
        decrypted_sever_login_info["user"]["secret_key_nonce"],
    )  # The user's secret key

    # 5. Now we can start actual reading the datastore and secrets e.g. to read the datastore:
    content = api_read_datastores(token, session_secret_key)

    # 6. Read content of the first password datastore including all its shares, all secrets and filter the secrets
    datastore_id = None
    for datastore in content["datastores"]:
        if datastore["type"] != "password":
            continue
        datastore_id = datastore["id"]
        datastore_read_result = api_read_datastore(
            token, session_secret_key, datastore["id"]
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
            "No password datastore yet found, please create one for the user first with the webclient."
        )
        return

    # 7. Add neccessary identifiers to existing datastore and append imported data as a folder
    datastore_content["datastore_id"] = datastore_id

    if not datastore_content.get("folders"):
        datastore_content["folders"] = []

    datastore_content["folders"].append(
        import_kdbx_file(
            keepass_database_path,
            keepass_database_password,
            datastore_id,
            token,
            session_secret_key,
        )
    )

    if not datastore_content.get("items"):
        datastore_content["items"] = []

    # 8. Encrypt new datastore structure
    encrypted_datastore = encrypt_symmetric(
        json.dumps(datastore_content), datastore_secret
    )

    # 9. Write new datastore structure
    api_write_datastore(
        token,
        session_secret_key,
        datastore_id,
        encrypted_datastore["text"],
        encrypted_datastore["nonce"],
    )

    # Logout
    api_logout(token, session_secret_key)

    print(f"\nImport complete! Successfully imported database.")


if __name__ == "__main__":
    main()
