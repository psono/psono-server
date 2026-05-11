"""
Repairs password datastore entries whose "name" value is not a string.

This can happen with older KeePass XML imports where numeric-looking XML values
were imported as JSON numbers. Affected clients may fail during search because
they expect folder and item names to be strings.

Requirements:
- unrestricted API key
- read permission
- write permission when APPLY_CHANGES is True

The script defaults to dry-run mode. Review the printed changes first, then set
APPLY_CHANGES to True and run it again to write the repaired datastore.

For affected website_password items, the linked secret's website_password_title
is also set to the repaired string item name.
"""

import binascii
import json
import socket

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
APPLY_CHANGES = True


def get_device_description():
    """
    This info is later shown in the "Open sessions" overview in the client.
    """
    return "Repair Datastore Names Script " + socket.gethostname()


def generate_client_login_info():
    """
    Generates and signs the login info.
    """
    box = PrivateKey.generate()
    session_private_key = box.encode(encoder=nacl.encoding.HexEncoder).decode()
    session_public_key = box.public_key.encode(
        encoder=nacl.encoding.HexEncoder
    ).decode()

    info = json.dumps(
        {
            "api_key_id": api_key_id,
            "session_public_key": session_public_key,
            "device_description": get_device_description(),
        }
    )

    signing_box = nacl.signing.SigningKey(
        api_key_private_key, encoder=nacl.encoding.HexEncoder
    )
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
    Decrypts the server login info.
    """
    crypto_box = Box(
        PrivateKey(session_private_key, encoder=nacl.encoding.HexEncoder),
        PublicKey(session_public_key, encoder=nacl.encoding.HexEncoder),
    )

    login_info = nacl.encoding.HexEncoder.decode(login_info_hex)
    login_info_nonce = nacl.encoding.HexEncoder.decode(login_info_nonce_hex)

    return json.loads(crypto_box.decrypt(login_info, login_info_nonce).decode())


def verify_signature(login_info, login_info_signature):
    """
    Validates the server signature.
    """
    verify_key = nacl.signing.VerifyKey(
        server_signature, encoder=nacl.encoding.HexEncoder
    )
    verify_key.verify(login_info.encode(), binascii.unhexlify(login_info_signature))


def decrypt_symmetric(text_hex, nonce_hex, secret):
    """
    Decrypts encrypted text with nonce and a symmetric secret.
    """
    text = nacl.encoding.HexEncoder.decode(text_hex)
    nonce = nacl.encoding.HexEncoder.decode(nonce_hex)
    secret_box = nacl.secret.SecretBox(secret, encoder=nacl.encoding.HexEncoder)

    return secret_box.decrypt(text, nonce)


def encrypt_symmetric(msg, secret):
    """
    Encrypts a string with a random nonce and a symmetric secret.
    """
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    secret_box = nacl.secret.SecretBox(secret, encoder=nacl.encoding.HexEncoder)
    encrypted = secret_box.encrypt(msg.encode(), nonce)
    text = encrypted[len(nonce) :]

    return {
        "text": nacl.encoding.HexEncoder.encode(text).decode(),
        "nonce": nacl.encoding.HexEncoder.encode(nonce).decode(),
    }


def decrypt_with_api_secret_key(secret_hex, secret_nonce_hex):
    """
    Decrypts anything encrypted with the API key secret.
    """
    return decrypt_symmetric(secret_hex, secret_nonce_hex, api_key_secret_key)


def api_request(method, endpoint, data=None, token=None, session_secret_key=None):
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = "Token " + token

    if session_secret_key and data:
        data = json.dumps(encrypt_symmetric(data, session_secret_key))

    response = requests.request(
        method, server_url + endpoint, data=data, headers=headers, verify=SSL_VERIFY
    )
    response.raise_for_status()

    if not session_secret_key:
        return response.json()

    encrypted_content = response.json()
    decrypted_content = decrypt_symmetric(
        encrypted_content["text"], encrypted_content["nonce"], session_secret_key
    )
    return json.loads(decrypted_content)


def api_login(client_login_info):
    return api_request("POST", "/api-key/login/", json.dumps(client_login_info))


def api_logout(token, session_secret_key):
    return api_request(
        "POST",
        "/authentication/logout/",
        token=token,
        session_secret_key=session_secret_key,
    )


def api_read_datastores(token, session_secret_key):
    return api_request(
        "GET", "/datastore/", token=token, session_secret_key=session_secret_key
    )


def api_read_datastore(token, session_secret_key, datastore_id):
    return api_request(
        "GET",
        "/datastore/" + datastore_id + "/",
        token=token,
        session_secret_key=session_secret_key,
    )


def api_write_datastore(
    token, session_secret_key, datastore_id, encrypted_data, encrypted_data_nonce
):
    data = json.dumps(
        {
            "datastore_id": datastore_id,
            "data": encrypted_data,
            "data_nonce": encrypted_data_nonce,
        }
    )

    return api_request(
        "POST",
        "/datastore/",
        data=data,
        token=token,
        session_secret_key=session_secret_key,
    )


def api_read_secret(token, session_secret_key, secret_id):
    return api_request(
        "GET",
        "/secret/" + secret_id + "/",
        token=token,
        session_secret_key=session_secret_key,
    )


def api_update_secret(token, session_secret_key, secret_id, data, data_nonce):
    payload = json.dumps(
        {"secret_id": secret_id, "data": data, "data_nonce": data_nonce}
    )

    return api_request(
        "POST",
        "/secret/",
        data=payload,
        token=token,
        session_secret_key=session_secret_key,
    )


def stringify_name(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def repair_names(node, path="datastore"):
    """
    Converts non-string "name" values to strings recursively.

    Returns a list of repaired paths for reporting.
    """
    repaired = []

    if isinstance(node, dict):
        if (
            "name" in node
            and node["name"] is not None
            and not isinstance(node["name"], str)
        ):
            old_value = node["name"]
            node["name"] = stringify_name(old_value)
            change = {
                "path": path + ".name",
                "old_type": type(old_value).__name__,
                "old_value": old_value,
                "new_value": node["name"],
            }
            if (
                node.get("type") == "website_password"
                and node.get("secret_id")
                and node.get("secret_key")
            ):
                change["secret_id"] = node["secret_id"]
                change["secret_key"] = node["secret_key"]
            repaired.append(change)

        for key, value in node.items():
            if isinstance(value, (dict, list)):
                repaired.extend(repair_names(value, path + "." + key))

    elif isinstance(node, list):
        for index, value in enumerate(node):
            if isinstance(value, (dict, list)):
                repaired.extend(repair_names(value, path + "[" + str(index) + "]"))

    return repaired


def read_password_datastore(token, session_secret_key, user_secret_key, datastore):
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

    return datastore_secret, datastore_content


def repair_website_password_titles(token, session_secret_key, repaired_names):
    repaired_titles = []

    for change in repaired_names:
        if "secret_id" not in change or "secret_key" not in change:
            continue

        secret_read_result = api_read_secret(
            token, session_secret_key, change["secret_id"]
        )
        secret_content = json.loads(
            decrypt_symmetric(
                secret_read_result["data"],
                secret_read_result["data_nonce"],
                change["secret_key"],
            )
        )

        new_value = change["new_value"]
        old_value = secret_content.get("website_password_title")
        if old_value == new_value:
            continue

        secret_content["website_password_title"] = new_value
        title_change = {
            "path": change["path"].replace(".name", ".website_password_title"),
            "secret_id": change["secret_id"],
            "old_type": type(old_value).__name__
            if old_value is not None
            else "missing",
            "old_value": old_value,
            "new_value": new_value,
            "secret_content": secret_content,
            "secret_key": change["secret_key"],
        }
        repaired_titles.append(title_change)

    return repaired_titles


def write_repaired_website_password_titles(token, session_secret_key, repaired_titles):
    for change in repaired_titles:
        encrypted_secret = encrypt_symmetric(
            json.dumps(change["secret_content"]), change["secret_key"]
        )
        api_update_secret(
            token,
            session_secret_key,
            change["secret_id"],
            encrypted_secret["text"],
            encrypted_secret["nonce"],
        )


def main():
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

    try:
        if decrypted_server_login_info["api_key_restrict_to_secrets"]:
            print("api key is restricted. it cannot repair datastores")
            return
        if not decrypted_server_login_info["api_key_read"]:
            print("api key does not allow read. Please allow read first")
            return
        if APPLY_CHANGES and not decrypted_server_login_info["api_key_write"]:
            print("api key does not allow write. Please allow write first")
            return

        user_secret_key = decrypt_with_api_secret_key(
            decrypted_server_login_info["user"]["secret_key"],
            decrypted_server_login_info["user"]["secret_key_nonce"],
        )

        content = api_read_datastores(token, session_secret_key)
        changed_datastores = 0
        changed_names = 0
        changed_titles = 0

        for datastore in content["datastores"]:
            if datastore["type"] != "password":
                continue

            datastore_secret, datastore_content = read_password_datastore(
                token, session_secret_key, user_secret_key, datastore
            )
            repaired = repair_names(datastore_content)
            repaired_titles = repair_website_password_titles(
                token, session_secret_key, repaired
            )

            if not repaired and not repaired_titles:
                print("Datastore " + datastore["id"] + ": no non-string names found")
                continue

            changed_datastores += 1
            changed_names += len(repaired)
            print(
                "Datastore "
                + datastore["id"]
                + ": found "
                + str(len(repaired))
                + " non-string name value(s)"
            )
            for change in repaired:
                print(
                    "  "
                    + change["path"]
                    + " ("
                    + change["old_type"]
                    + "): "
                    + repr(change["old_value"])
                    + " -> "
                    + repr(change["new_value"])
                )
            if repaired_titles:
                changed_titles += len(repaired_titles)
                print(
                    "  found "
                    + str(len(repaired_titles))
                    + " affected website_password_title value(s)"
                )
                for change in repaired_titles:
                    print(
                        "  "
                        + change["path"]
                        + " ("
                        + change["old_type"]
                        + "): "
                        + repr(change["old_value"])
                        + " -> "
                        + repr(change["new_value"])
                    )

            if APPLY_CHANGES:
                write_repaired_website_password_titles(
                    token, session_secret_key, repaired_titles
                )
                encrypted_datastore = encrypt_symmetric(
                    json.dumps(datastore_content), datastore_secret
                )
                api_write_datastore(
                    token,
                    session_secret_key,
                    datastore["id"],
                    encrypted_datastore["text"],
                    encrypted_datastore["nonce"],
                )
                print("  written")
            else:
                print("  dry-run only, set APPLY_CHANGES = True to write")

        print(
            "Finished. Datastores with changes: "
            + str(changed_datastores)
            + ", repaired names: "
            + str(changed_names)
            + ", repaired website_password_title values: "
            + str(changed_titles)
        )
    finally:
        api_logout(token, session_secret_key)


if __name__ == "__main__":
    main()
