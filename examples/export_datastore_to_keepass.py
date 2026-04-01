"""
A small demo script that shows how to export the datastore (unrestricted API key)
"""

import requests
import json
import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
import binascii
import socket
from pykeepass import PyKeePass, create_database
import pprint

keepass_database_path = "/path/to/export.kdbx"
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


def get_device_description():
    """
    This info is later shown in the "Open sessions" overview in the client. Should be something so the user knows where
    this session is coming from.

    :return:
    :rtype:
    """
    return "Console Client " + socket.gethostname()


def generate_client_login_info():
    """
    Generates and signs the login info
    Returns a tuple of the session private key and the login info

    :return:
    :rtype:
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
    Takes the login info and nonce together with the session public and private key.
    Will decrypt the login info and interpret it as json and return the json parsed object.
    :param login_info:
    :type login_info:
    :param login_info_nonce:
    :type login_info_nonce:
    :param session_public_key:
    :type session_public_key:
    :param session_private_key:
    :type session_private_key:

    :return:
    :rtype:
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
    Takes the login info and the provided signature and will validate it with the help of server_signature.

    Will raise an exception if it does not match.

    :param login_info:
    :type login_info:
    :param login_info_signature:
    :type login_info_signature:

    :return:
    :rtype:
    """

    verify_key = nacl.signing.VerifyKey(
        server_signature, encoder=nacl.encoding.HexEncoder
    )

    verify_key.verify(login_info.encode(), binascii.unhexlify(login_info_signature))


def decrypt_symmetric(text_hex, nonce_hex, secret):
    """
    Decryts an encrypted text with nonce with the given secret

    :param text_hex:
    :type text_hex:
    :param nonce_hex:
    :type nonce_hex:
    :param secret:
    :type secret:
    :return:
    :rtype:
    """

    text = nacl.encoding.HexEncoder.decode(text_hex)
    secret_box = nacl.secret.SecretBox(secret, encoder=nacl.encoding.HexEncoder)

    if nonce_hex is not None:
        nonce = nacl.encoding.HexEncoder.decode(nonce_hex)
        return secret_box.decrypt(text, nonce)

    return secret_box.decrypt(text)


def encrypt_symmetric(msg, secret):
    """
    Encrypts a message with a random nonce and a given secret

    :param msg: The message as str
    :type msg: str
    :param secret: The secret as hex encoded str
    :type secret: str
    :return: A dict, containing the encrypted message with the text and nonce being returned separately
    :rtype: dict
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
    take anything that is encrypted with the api keys secret and decrypts it. e.g. the users secret and private key

    :param secret_hex:
    :type secret_hex:
    :param secret_nonce_hex:
    :type secret_nonce_hex:

    :return:
    :rtype:
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

    :param client_login_info:
    :type client_login_info:

    :return:
    :rtype:
    """

    method = "POST"
    endpoint = "/api-key/login/"
    data = json.dumps(client_login_info)

    return api_request(method, endpoint, data)


def api_read_datastores(token, session_secret_key):
    """
    Reads all datastores

    :param token:
    :type token:
    :param session_secret_key:
    :type session_secret_key:
    :return:
    :rtype:
    """

    method = "GET"
    endpoint = "/datastore/"

    return api_request(
        method, endpoint, token=token, session_secret_key=session_secret_key
    )


def api_logout(token, session_secret_key):
    """
    Destroys the session again.

    :param token:
    :type token:
    :param session_secret_key:
    :type session_secret_key:
    :return:
    :rtype:
    """

    method = "POST"
    endpoint = "/authentication/logout/"

    return api_request(
        method, endpoint, token=token, session_secret_key=session_secret_key
    )


def api_read_datastore(token, session_secret_key, datastore_id):
    """
    Reads the content of a specific datastore

    :param token:
    :type token:
    :param session_secret_key:
    :type session_secret_key:
    :param datastore_id:
    :type datastore_id:
    :return:
    :rtype:
    """

    method = "GET"
    endpoint = "/datastore/" + datastore_id + "/"

    return api_request(
        method, endpoint, token=token, session_secret_key=session_secret_key
    )


def api_read_secret(token, session_secret_key, secret_id):
    """
    Reads the content of a specific secret

    :param token:
    :type token:
    :param session_secret_key:
    :type session_secret_key:
    :param secret_id:
    :type secret_id:
    :return:
    :rtype:
    """

    method = "GET"
    endpoint = "/secret/" + secret_id + "/"

    return api_request(
        method, endpoint, token=token, session_secret_key=session_secret_key
    )


def api_read_share(token, session_secret_key, share_id):
    """
    Reads the content of a specific share

    :param token:
    :type token:
    :param session_secret_key:
    :type session_secret_key:
    :param secret_id:
    :type secret_id:
    :return:
    :rtype:
    """

    method = "GET"
    endpoint = "/share/" + share_id + "/"

    return api_request(
        method, endpoint, token=token, session_secret_key=session_secret_key
    )


def get_all_shares(folder, token, session_secret_key):

    def handle_share(share):
        share_read_result = api_read_share(token, session_secret_key, share["share_id"])
        share_content = None
        try:
            share_content = json.loads(
                decrypt_symmetric(
                    share_read_result["data"],
                    share_read_result["data_nonce"],
                    share["share_secret_key"],
                )
            )
        except:
            pass

        return share_content

    if "folders" in folder:
        new_folders = []
        for f in folder["folders"]:
            if "share_id" in f and "share_secret_key" in f:
                f = handle_share(f)
            if f is None:
                continue
            new_folders.append(f)

            get_all_shares(f, token, session_secret_key)

        folder["folders"] = new_folders

    if "items" in folder:
        new_items = []
        for i in folder["items"]:
            if "share_id" in i and "share_secret_key" in i:
                i = handle_share(i)
            if i is None:
                continue
            new_items.append(i)

        folder["items"] = new_items


def get_all_secrets(
    datastore, token, session_secret_key, include_trash_bin_items=False
):

    def handle_items(items):
        for item in items:
            if not "secret_id" in item:
                continue
            if not "secret_key" in item:
                continue

            if not include_trash_bin_items and "deleted" in item and item["deleted"]:
                continue

            secret_read_result = api_read_secret(
                token, session_secret_key, item["secret_id"]
            )
            if "non_field_errors" in secret_read_result:
                # we skip over entries that don't exist or that we have lost permission for
                continue
            secret_content = json.loads(
                decrypt_symmetric(
                    secret_read_result["data"],
                    secret_read_result["data_nonce"],
                    item["secret_key"],
                )
            )

            for key in secret_content.keys():
                item[key] = secret_content[key]

            item["create_date"] = secret_read_result["create_date"]
            item["write_date"] = secret_read_result["write_date"]
            item["callback_url"] = secret_read_result["callback_url"]
            item["callback_user"] = secret_read_result["callback_user"]
            item["callback_pass"] = secret_read_result["callback_pass"]

    def handle_folders(folders):
        for folder in folders:
            if "folders" in folder:
                handle_folders(folder["folders"])

            if "items" in folder:
                handle_items(folder["items"])

    if "folders" in datastore:
        handle_folders(datastore["folders"])

    if "items" in datastore:
        handle_items(datastore["items"])


def filter_datastore_export(folder, include_trash_bin_items=False):

    unwanted_folder_properties = [
        "id",
        "datastore_id",
        "is_folder",
        "parent_datastore_id",
        "share_index",
        "parent_share_id",
        "share_id",
        "path",
        "share_rights",
        "share_secret_key",
    ]

    unwanted_item_properties = [
        "id",
        "datastore_id",
        "is_folder",
        "parent_datastore_id",
        "parent_share_id",
        "secret_id",
        "secret_key",
        "share_id",
        "path",
        "share_rights",
        "share_secret_key",
    ]

    # filter out unwanted folder properties
    for p in unwanted_folder_properties:
        if p in folder:
            del folder[p]

    # Delete items that have been marked as deleted if includeTrashBinItems is not set
    if "items" in folder and not include_trash_bin_items:
        folder["items"] = [
            i for i in folder["items"] if "deleted" not in i or not i["deleted"]
        ]

    # Delete items attribute if its empty
    if "items" in folder and len(folder["items"]) == 0:
        del folder["items"]

    # filter out unwanted item properties
    if "items" in folder:
        for p in unwanted_item_properties:
            for item in folder["items"]:
                if p in item:
                    del item[p]

    # Delete folders that have been marked as deleted if includeTrashBinItems is not set
    if "folders" in folder and not include_trash_bin_items:
        folder["folders"] = [
            f for f in folder["folders"] if "deleted" not in f or not f["deleted"]
        ]

    # Delete folders attribute if its empty
    if "folders" in folder and len(folder["folders"]) == 0:
        del folder["folders"]

    # filter folders recursive
    if "folders" in folder:
        folder["folders"] = [filter_datastore_export(f) for f in folder["folders"]]

    return folder


def escape_for_xpath(string=""):
    return string.replace(r'"', r"'")


def create_keepass_database(
    keepass, datastore_content, base_group, token, session_secret_key
):
    for folder in datastore_content.get("folders", []):
        current_group = create_keepass_database_group(
            keepass, folder.get("name", "Unnamed Entry"), base_group
        )
        create_keepass_database(
            keepass, folder, current_group, token, session_secret_key
        )
    for item in datastore_content.get("items", []):
        create_keepass_database_entry(
            keepass, item, base_group, token, session_secret_key
        )


def create_keepass_database_group(keepass, folder_name, base_group):
    return keepass.add_group(base_group, escape_for_xpath(folder_name))


def create_keepass_database_entry(keepass, item, base_group, token, session_secret_key):
    if item.get("type", "") == "website_password":
        entry = keepass.add_entry(
            base_group,
            escape_for_xpath(item.get("name", "Unnamed Entry") or "Unnamed Entry"),
            item.get("website_password_username", "") or "",
            item.get("website_password_password", "") or "",
            item.get("website_password_url", "") or "",
            item.get("website_password_notes", "") or "",
            None,
            None,
            None,
            None,
            True,
        )

        for attachment in item.get("attachments", []):
            file_name = (
                attachment.get("filename", "unnamed_binary.bin") or "unnamed_binary.bin"
            )
            downloaded_file = download_file(attachment, token, session_secret_key)
            binary_id = keepass.add_binary(downloaded_file)
            entry.add_attachment(binary_id, file_name)

        return entry

    if item.get("type", "") == "application_password":
        entry = keepass.add_entry(
            base_group,
            escape_for_xpath(item.get("name", "Unnamed Entry") or "Unnamed Entry"),
            item.get("application_password_username", "") or "",
            item.get("application_password_password", "") or "",
            "",
            item.get("application_password_notes", "") or "",
            None,
            None,
            None,
            None,
            True,
        )

        for attachment in item.get("attachments", []):
            file_name = (
                attachment.get("filename", "unnamed_binary.bin") or "unnamed_binary.bin"
            )
            downloaded_file = download_file(attachment, token, session_secret_key)
            binary_id = keepass.add_binary(downloaded_file)
            entry.add_attachment(binary_id, file_name)

        return entry

    if item.get("type", "") == "file":
        entry = keepass.add_entry(
            base_group,
            escape_for_xpath(item.get("name", "Unnamed Entry") or "Unnamed Entry"),
            "",
            "",
            "",
            "",
            None,
            None,
            None,
            None,
            True,
        )

        file_name = item.get("filename", "unnamed_binary.bin") or "unnamed_binary.bin"
        downloaded_file = download_file(item, token, session_secret_key)
        binary_id = keepass.add_binary(downloaded_file)
        entry.add_attachment(binary_id, file_name)

        return entry

    if item.get("type", "") == "elster_certificate":
        entry = keepass.add_entry(
            base_group,
            escape_for_xpath(item.get("name", "Unnamed Entry") or "Unnamed Entry"),
            "",
            item.get("elster_certificate_password", "") or "",
            "",
            "",
            None,
            None,
            None,
            None,
            True,
        )

        file_name = (
            item.get("name", "unnamed_certificate") or "unnamed_binary.bin"
        ) + ".pfx"
        binary_id = keepass.add_binary(
            nacl.encoding.HexEncoder.decode(
                item.get("elster_certificate_file_content", "")
            )
        )
        entry.add_attachment(binary_id, file_name)

        return entry

    return


def write_keepass_database(
    datastore_content, file_path, password, token, session_secret_key
):
    keepass = create_database(file_path, password, keyfile=None, transformed_key=None)
    create_keepass_database(
        keepass, datastore_content, keepass.root_group, token, session_secret_key
    )
    return keepass.save()


def api_read_file_transfer_ids(token, session_secret_key, file_id):
    """
    Reads the content of a specific share

    :param token:
    :type token:
    :param session_secret_key:
    :type session_secret_key:
    :param file_id:
    :type file_id:
    :return:
    :rtype:
    """

    method = "GET"
    endpoint = "/file/" + file_id + "/"

    return api_request(
        method, endpoint, token=token, session_secret_key=session_secret_key
    )


def api_download_file(data=None):
    headers = {"content-type": "application/json"}
    return requests.request(
        "POST",
        fileserver_url + "/download/",
        data=json.dumps(data),
        headers=headers,
        verify=SSL_VERIFY,
        stream=True,
    ).content


def download_file(file_data, token, session_secret_key):

    file_transfer_ids = {}

    try:
        file_transfer_ids = api_read_file_transfer_ids(
            token, session_secret_key, file_data.get("file_id", "")
        )
    except:
        pprint.pprint(file_data)
        return

    print("download file: " + file_data.get("name", file_data.get("file_id", "")))

    if len(file_data.get("file_chunks", [])) > 35:
        print("skipped due to size limit")
        return None

    downloaded_chunks = b""

    for file_chunk in file_data.get("file_chunks", []):
        ticket_decrypted = {"hash_checksum": file_chunk.get("hash", "")}
        ticket_encrypted = encrypt_symmetric(
            json.dumps(ticket_decrypted),
            file_transfer_ids.get("file_transfer_secret_key", ""),
        )

        request_data = {
            "file_transfer_id": file_transfer_ids.get("file_transfer_id", ""),
            "ticket": ticket_encrypted.get("text", ""),
            "ticket_nonce": ticket_encrypted.get("nonce", ""),
        }

        downloaded_chunks += decrypt_symmetric(
            api_download_file(request_data).hex(),
            None,
            file_data.get("file_secret_key", ""),
        )

    return downloaded_chunks


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
    datastore_content = None
    for datastore in content["datastores"]:
        if datastore["type"] != "password":
            continue
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

    # 7. Reads all shares recursively
    get_all_shares(datastore_content, token, session_secret_key)

    # 8. Reads all the secrets
    get_all_secrets(datastore_content, token, session_secret_key)

    # 9. Filter the datastore content to remove unnecessary data
    datastore_content = filter_datastore_export(datastore_content)

    # 10. Write Keepass Database
    write_keepass_database(
        datastore_content,
        keepass_database_path,
        keepass_database_password,
        token,
        session_secret_key,
    )

    # 11. Logout
    api_logout(token, session_secret_key)


if __name__ == "__main__":
    main()
