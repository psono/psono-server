"""
Create a group (if missing) and invite a user to it using an unrestricted API key session.

Usage:
    python create_group_and_invite_user.py "My Group" "user@example.com"
"""

import argparse
import binascii
import json
import socket

import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.utils
import requests
from nacl.public import Box, PrivateKey, PublicKey


api_key_id = "e1cd9c08-4887-4b06-a26d-c92b1e84f49e"
api_key_private_key = "0bbc18ac5d82ffabe324722ade66d99378c7772eef727e8e255e38ad2ab9f50c"
api_key_secret_key = "04ab9b23de0f710e2c521fb1fbb77802dbd9f1586c31fd454b0497f0aa94acb4"
server_url = "https://psonoclient.chickahoona.com/server"
server_public_key = "02da2ad857321d701d754a7e60d0a147cdbc400ff4465e1f57bc2d9fbfeddf0b"
server_signature = "4ce9e761e1d458fe18af577c50eb8249a0de535c9bd6b7a97885c331b46dcbd1"

SSL_VERIFY = True


def get_device_description():
    return "Console Client " + socket.gethostname()


def generate_client_login_info():
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

    signing_key = nacl.signing.SigningKey(
        api_key_private_key, encoder=nacl.encoding.HexEncoder
    )
    signature = binascii.hexlify(signing_key.sign(info.encode()).signature).decode()

    return session_private_key, {"info": info, "signature": signature}


def verify_signature(login_info, login_info_signature):
    verify_key = nacl.signing.VerifyKey(
        server_signature, encoder=nacl.encoding.HexEncoder
    )
    verify_key.verify(login_info.encode(), binascii.unhexlify(login_info_signature))


def decrypt_server_login_info(
    login_info_hex, login_info_nonce_hex, server_session_public_key, session_private_key
):
    crypto_box = Box(
        PrivateKey(session_private_key, encoder=nacl.encoding.HexEncoder),
        PublicKey(server_session_public_key, encoder=nacl.encoding.HexEncoder),
    )

    login_info = nacl.encoding.HexEncoder.decode(login_info_hex)
    login_info_nonce = nacl.encoding.HexEncoder.decode(login_info_nonce_hex)
    return json.loads(crypto_box.decrypt(login_info, login_info_nonce).decode())


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

    return {
        "text": nacl.encoding.HexEncoder.encode(text).decode(),
        "nonce": nacl.encoding.HexEncoder.encode(nonce).decode(),
    }


def decrypt_with_api_secret_key(secret_hex, secret_nonce_hex):
    return decrypt_symmetric(secret_hex, secret_nonce_hex, api_key_secret_key).decode()


def encrypt_asymmetric(msg, recipient_public_key, sender_private_key):
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    crypto_box = Box(
        PrivateKey(sender_private_key, encoder=nacl.encoding.HexEncoder),
        PublicKey(recipient_public_key, encoder=nacl.encoding.HexEncoder),
    )
    encrypted = crypto_box.encrypt(msg.encode(), nonce)
    text = encrypted[len(nonce) :]
    return {
        "text": nacl.encoding.HexEncoder.encode(text).decode(),
        "nonce": nacl.encoding.HexEncoder.encode(nonce).decode(),
    }


def decrypt_asymmetric(text_hex, nonce_hex, sender_public_key, recipient_private_key):
    crypto_box = Box(
        PrivateKey(recipient_private_key, encoder=nacl.encoding.HexEncoder),
        PublicKey(sender_public_key, encoder=nacl.encoding.HexEncoder),
    )
    text = nacl.encoding.HexEncoder.decode(text_hex)
    nonce = nacl.encoding.HexEncoder.decode(nonce_hex)
    return crypto_box.decrypt(text, nonce).decode()


def api_request(method, endpoint, data=None, token=None, session_secret_key=None):
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = "Token " + token

    payload = data
    if session_secret_key and data is not None:
        payload = json.dumps(encrypt_symmetric(data, session_secret_key))

    response = requests.request(
        method,
        server_url + endpoint,
        data=payload,
        headers=headers,
        verify=SSL_VERIFY,
    )

    content = response.json() if response.content else {}
    if not response.ok:
        raise RuntimeError(
            f"API request failed ({response.status_code}) {endpoint}: {content}"
        )

    if not session_secret_key:
        return content

    decrypted = decrypt_symmetric(content["text"], content["nonce"], session_secret_key)
    return json.loads(decrypted)


def api_login(client_login_info):
    return api_request("POST", "/api-key/login/", data=json.dumps(client_login_info))


def api_logout(token, session_secret_key):
    return api_request(
        "POST",
        "/authentication/logout/",
        token=token,
        session_secret_key=session_secret_key,
    )


def api_read_groups(token, session_secret_key):
    return api_request(
        "GET", "/group/", token=token, session_secret_key=session_secret_key
    )


def api_read_group(token, session_secret_key, group_id):
    return api_request(
        "GET", f"/group/{group_id}/", token=token, session_secret_key=session_secret_key
    )


def api_create_group(
    token,
    session_secret_key,
    name,
    encrypted_secret_key,
    encrypted_secret_key_nonce,
    encrypted_private_key,
    encrypted_private_key_nonce,
    public_key,
):
    data = json.dumps(
        {
            "name": name,
            "secret_key": encrypted_secret_key,
            "secret_key_nonce": encrypted_secret_key_nonce,
            "private_key": encrypted_private_key,
            "private_key_nonce": encrypted_private_key_nonce,
            "public_key": public_key,
        }
    )
    return api_request(
        "PUT", "/group/", data=data, token=token, session_secret_key=session_secret_key
    )


def api_user_search(token, session_secret_key, username):
    data = json.dumps({"user_username": username})
    return api_request(
        "POST",
        "/user/search/",
        data=data,
        token=token,
        session_secret_key=session_secret_key,
    )


def api_create_membership(
    token,
    session_secret_key,
    group_id,
    user_id,
    secret_key,
    secret_key_nonce,
    private_key,
    private_key_nonce,
    group_admin=False,
    share_admin=False,
):
    data = json.dumps(
        {
            "group_id": group_id,
            "user_id": user_id,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "secret_key_type": "asymmetric",
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "private_key_type": "asymmetric",
            "group_admin": group_admin,
            "share_admin": share_admin,
        }
    )
    return api_request(
        "PUT",
        "/membership/",
        data=data,
        token=token,
        session_secret_key=session_secret_key,
    )


def get_exact_user(token, session_secret_key, username):
    result = api_user_search(token, session_secret_key, username)
    users = result if isinstance(result, list) else [result]
    expected = username.strip().lower()

    for user in users:
        if str(user.get("username", "")).strip().lower() == expected:
            return user
    return None


def decrypt_group_key_for_current_user(group, user_secret_key, user_private_key):
    if group["secret_key_type"] == "symmetric":
        group_secret_key = decrypt_symmetric(
            group["secret_key"], group["secret_key_nonce"], user_secret_key
        ).decode()
    else:
        group_secret_key = decrypt_asymmetric(
            group["secret_key"],
            group["secret_key_nonce"],
            group["public_key"],
            user_private_key,
        )

    if group["private_key_type"] == "symmetric":
        group_private_key = decrypt_symmetric(
            group["private_key"], group["private_key_nonce"], user_secret_key
        ).decode()
    else:
        group_private_key = decrypt_asymmetric(
            group["private_key"],
            group["private_key_nonce"],
            group["public_key"],
            user_private_key,
        )

    return group_secret_key, group_private_key


def get_or_create_group(token, session_secret_key, user_secret_key, group_name):
    groups_result = api_read_groups(token, session_secret_key)
    groups = groups_result.get("groups", [])

    for group in groups:
        if group.get("name") == group_name:
            return group, False

    group_secret_key = nacl.encoding.HexEncoder.encode(
        nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    ).decode()
    group_keypair = PrivateKey.generate()
    group_private_key = group_keypair.encode(encoder=nacl.encoding.HexEncoder).decode()
    group_public_key = group_keypair.public_key.encode(
        encoder=nacl.encoding.HexEncoder
    ).decode()

    group_secret_key_enc = encrypt_symmetric(group_secret_key, user_secret_key)
    group_private_key_enc = encrypt_symmetric(group_private_key, user_secret_key)

    created_group = api_create_group(
        token,
        session_secret_key,
        group_name,
        group_secret_key_enc["text"],
        group_secret_key_enc["nonce"],
        group_private_key_enc["text"],
        group_private_key_enc["nonce"],
        group_public_key,
    )
    return created_group, True


def invite_user_to_group(
    token,
    session_secret_key,
    user_secret_key,
    user_private_key,
    group_id,
    username,
):
    group_details = api_read_group(token, session_secret_key, group_id)

    members = group_details.get("members", [])
    expected_username = username.strip().lower()
    for member in members:
        if str(member.get("name", "")).strip().lower() == expected_username:
            return False, "User already has a membership for this group"

    target_user = get_exact_user(token, session_secret_key, username)
    if not target_user:
        raise RuntimeError(f"User '{username}' not found")

    group_secret_key, group_private_key = decrypt_group_key_for_current_user(
        group_details, user_secret_key, user_private_key
    )

    encrypted_group_secret_key = encrypt_asymmetric(
        group_secret_key,
        target_user["public_key"],
        group_private_key,
    )
    encrypted_group_private_key = encrypt_asymmetric(
        group_private_key,
        target_user["public_key"],
        group_private_key,
    )

    api_create_membership(
        token,
        session_secret_key,
        group_id,
        target_user["id"],
        encrypted_group_secret_key["text"],
        encrypted_group_secret_key["nonce"],
        encrypted_group_private_key["text"],
        encrypted_group_private_key["nonce"],
    )
    return True, "Invitation created"


def create_session():
    session_private_key, client_login_info = generate_client_login_info()
    login_response = api_login(client_login_info)

    verify_signature(
        login_response["login_info"], login_response["login_info_signature"]
    )

    login_info = decrypt_server_login_info(
        login_response["login_info"],
        login_response["login_info_nonce"],
        login_response["server_session_public_key"],
        session_private_key,
    )

    if login_info.get("api_key_restrict_to_secrets"):
        raise RuntimeError("API key is restricted to secrets and cannot manage groups")
    if not login_info.get("api_key_read"):
        raise RuntimeError("API key requires read permission")
    if not login_info.get("api_key_write"):
        raise RuntimeError("API key requires write permission")

    user_secret_key = decrypt_with_api_secret_key(
        login_info["user"]["secret_key"], login_info["user"]["secret_key_nonce"]
    )
    user_private_key = decrypt_with_api_secret_key(
        login_info["user"]["private_key"], login_info["user"]["private_key_nonce"]
    )

    return {
        "token": login_info["token"],
        "session_secret_key": login_info["session_secret_key"],
        "user_secret_key": user_secret_key,
        "user_private_key": user_private_key,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a Psono group (if needed) and invite a user"
    )
    parser.add_argument("group_name", help="Name of the group to create or reuse")
    parser.add_argument("username", help="Username to invite to the group")
    return parser.parse_args()


def main():
    args = parse_args()
    session = create_session()
    token = session["token"]
    session_secret_key = session["session_secret_key"]

    try:
        group, created = get_or_create_group(
            token,
            session_secret_key,
            session["user_secret_key"],
            args.group_name,
        )
        if created:
            print(f"Created group '{args.group_name}' ({group['group_id']})")
        else:
            print(f"Using existing group '{group['name']}' ({group['group_id']})")

        invited, message = invite_user_to_group(
            token,
            session_secret_key,
            session["user_secret_key"],
            session["user_private_key"],
            group["group_id"],
            args.username,
        )
        if invited:
            print(f"Invited '{args.username}' to '{group['name']}'")
        else:
            print(f"Skipped invite: {message}")
    finally:
        api_logout(token, session_secret_key)


if __name__ == "__main__":
    main()
