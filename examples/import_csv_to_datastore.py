"""
A script that imports secrets from a CSV file into the datastore with folder structure

CSV Format (semicolon-separated):
"safe";"Path";"name of object";"login/username";"address";"password"

Example:
"myid";"Root";"root account on test server";"root";"192.168.1.1";"secretpass"
"myid";"Root\\Subfolder";"google account";"myuser@gmail.com";"https://google.com";"mypass123"
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
import csv
import sys
import os
import re
import hashlib

api_key_id = "e1cd9c08-4887-4b06-a26d-c92b1e84f49e"
api_key_private_key = "0bbc18ac5d82ffabe324722ade66d99378c7772eef727e8e255e38ad2ab9f50c"
api_key_secret_key = "04ab9b23de0f710e2c521fb1fbb77802dbd9f1586c31fd454b0497f0aa94acb4"
server_url = "https://psonoclient.chickahoona.com/server"
server_public_key = "02da2ad857321d701d754a7e60d0a147cdbc400ff4465e1f57bc2d9fbfeddf0b"
server_signature = "4ce9e761e1d458fe18af577c50eb8249a0de535c9bd6b7a97885c331b46dcbd1"

SSL_VERIFY = True


def get_device_description():
    """
    This info is later shown in the "Open sessions" overview in the client.
    """
    return "CSV Import Script " + socket.gethostname()


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


def find_folder_by_name(folder_name, folder_list):
    """
    Searches for a folder by name in a list of folders
    """
    if not folder_list:
        return None
    for folder in folder_list:
        if folder.get("name") == folder_name:
            return folder
    return None


def create_folder_if_not_exist(folder_name, parent_folder):
    """
    Creates a new folder in the parent folder if it does not exist
    Returns the folder object
    """
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


def create_folder(folder_name, parent_folder):
    """
    Creates a new folder in the parent folder, always.
    Returns the folder object.
    """
    if "folders" not in parent_folder:
        parent_folder["folders"] = []

    folder = {
        "id": str(uuid.uuid4()),
        "name": folder_name,
    }

    parent_folder["folders"].append(folder)

    return folder


def create_shared_folder(
    token,
    session_secret_key,
    folder,
    datastore_content,
    datastore_id,
    user_secret_key,
):
    """
    Converts a folder reference in the datastore into a shared folder.
    Returns share_id, share_secret_key, share_content.
    """
    share_secret_key = nacl.encoding.HexEncoder.encode(
        nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    ).decode()

    share_content = {
        "name": folder["name"],
    }

    encrypted_share = encrypt_symmetric(json.dumps(share_content), share_secret_key)
    encrypted_share_key = encrypt_symmetric(share_secret_key, user_secret_key)

    result = api_create_share(
        token,
        session_secret_key,
        encrypted_share["text"],
        encrypted_share["nonce"],
        encrypted_share_key["text"],
        encrypted_share_key["nonce"],
        datastore_id,
        folder["id"],
    )

    share_id = result["share_id"]

    folder["share_id"] = share_id
    folder["share_secret_key"] = share_secret_key

    if "share_index" not in datastore_content:
        datastore_content["share_index"] = {}

    datastore_content["share_index"][share_id] = {
        "paths": [[folder["id"]]],
        "secret_key": share_secret_key,
    }

    return share_id, share_secret_key, share_content


def share_share_with_matching_user(
    token,
    session_secret_key,
    safe_name,
    share_id,
    share_secret_key,
    user_private_key,
):
    """
    Shares the share with the user if a username exactly matching the safe name exists.
    """
    target_user = get_user_by_exact_username(token, session_secret_key, safe_name)

    if not target_user:
        print(
            f"  No user found with username '{safe_name}'. Skipping share-right creation."
        )
        return

    target_public_key = target_user.get("public_key")
    target_user_id = target_user.get("id")
    target_username = target_user.get("username")

    if not target_public_key or not target_user_id:
        print(
            f"  User '{safe_name}' found but missing id/public_key. Skipping share-right creation."
        )
        return

    encrypted_share_key = encrypt_asymmetric(
        share_secret_key, target_public_key, user_private_key
    )
    encrypted_title = encrypt_asymmetric(safe_name, target_public_key, user_private_key)
    encrypted_type = encrypt_asymmetric("folder", target_public_key, user_private_key)

    api_create_share_right(
        token,
        session_secret_key,
        share_id,
        target_user_id,
        encrypted_share_key["text"],
        encrypted_share_key["nonce"],
        encrypted_title["text"],
        encrypted_title["nonce"],
        encrypted_type["text"],
        encrypted_type["nonce"],
    )

    print(f"  Shared safe '{safe_name}' with user '{target_username}'.")


def get_or_create_folder_path(path, datastore_content):
    """
    Navigates or creates the folder structure based on the path
    Path format: "Root" or "Root\\Subfolder\\Another"
    Returns the target folder
    """
    if not path or path.strip() == "":
        return datastore_content

    # Split the path by backslash
    path_parts = path.split("\\")

    # Remove "Root" if it's the first part, as it refers to the root of the datastore
    if path_parts[0].strip().lower() == "root":
        path_parts = path_parts[1:]

    # If no subfolders, return the datastore content itself (root level)
    if not path_parts or (len(path_parts) == 1 and path_parts[0].strip() == ""):
        return datastore_content

    # Navigate/create folder structure
    current_folder = datastore_content
    for folder_name in path_parts:
        folder_name = folder_name.strip()
        if folder_name:
            current_folder = create_folder_if_not_exist(folder_name, current_folder)

    return current_folder


def is_website_address(address):
    """
    Determines if an address looks like a website URL
    Returns True if it's a website, False otherwise
    """
    if not address or address.strip() == "":
        return False

    address = address.strip().lower()

    # Check if it starts with http:// or https://
    if address.startswith("http://") or address.startswith("https://"):
        return True

    # Check if it looks like a domain (contains a dot and has a TLD)
    # Common TLDs to check
    common_tlds = [
        ".com",
        ".org",
        ".net",
        ".edu",
        ".gov",
        ".io",
        ".co",
        ".uk",
        ".de",
        ".fr",
        ".au",
        ".ca",
        ".jp",
        ".cn",
    ]
    for tld in common_tlds:
        if tld in address:
            return True

    # Check if it looks like an IP address format (basic check)
    # Match patterns like 192.168.1.1 or with http path
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}"
    if re.match(ip_pattern, address):
        return True

    # Check if it has multiple dots (likely a domain like subdomain.example.com)
    if address.count(".") >= 1 and not address.endswith("."):
        # Check if it has at least one alphabetic character (not just numbers and dots)
        if any(c.isalpha() for c in address):
            return True

    return False


def create_website_password_secret(
    token,
    session_secret_key,
    name,
    username,
    address,
    password,
    folder,
    parent_id,
    parent_is_share=False,
):
    """
    Creates a website_password type secret
    """
    if "items" not in folder:
        folder["items"] = []

    secret_key = nacl.encoding.HexEncoder.encode(
        nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    ).decode()

    # Determine URL filter from address
    urlfilter = ""
    full_url = address if address else ""

    # Add https:// if no protocol specified
    if (
        address
        and not address.startswith("http://")
        and not address.startswith("https://")
    ):
        full_url = "https://" + address

    if address:
        try:
            from urllib.parse import urlparse

            parsed = urlparse(full_url)
            urlfilter = parsed.netloc if parsed.netloc else address
        except:
            urlfilter = address

    content = {
        "website_password_title": name,
        "website_password_url": full_url,
        "website_password_username": username if username else "",
        "website_password_password": password if password else "",
        "website_password_notes": "",
        "website_password_auto_submit": False,
        "website_password_url_filter": urlfilter,
        "website_password_allow_http": full_url.startswith("http://"),
    }

    encrypted_secret = encrypt_symmetric(json.dumps(content), secret_key)

    link_id = str(uuid.uuid4())

    result = api_create_secret(
        token,
        session_secret_key,
        encrypted_secret["text"],
        encrypted_secret["nonce"],
        link_id,
        parent_share_id=parent_id if parent_is_share else None,
        parent_datastore_id=parent_id if not parent_is_share else None,
    )

    item = {
        "id": link_id,
        "name": name,
        "type": "website_password",
        "secret_id": result["secret_id"],
        "secret_key": secret_key,
        "urlfilter": urlfilter,
    }

    if content["website_password_username"]:
        item["description"] = content["website_password_username"]

    if content["website_password_allow_http"]:
        item["allow_http"] = content["website_password_allow_http"]

    # Calculate password_hash - first 5 digits of SHA1 hash in hex notation
    if password:
        password_sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest()
        item["password_hash"] = password_sha1[:5].lower()
    else:
        item["password_hash"] = ""

    folder["items"].append(item)


def create_application_password_secret(
    token,
    session_secret_key,
    name,
    username,
    address,
    password,
    folder,
    parent_id,
    parent_is_share=False,
):
    """
    Creates an application_password type secret
    """
    if "items" not in folder:
        folder["items"] = []

    secret_key = nacl.encoding.HexEncoder.encode(
        nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    ).decode()

    content = {
        "application_password_title": name,
        "application_password_username": username if username else "",
        "application_password_password": password if password else "",
        "application_password_notes": address
        if address
        else "",  # Store address in notes for application passwords
    }

    encrypted_secret = encrypt_symmetric(json.dumps(content), secret_key)

    link_id = str(uuid.uuid4())

    result = api_create_secret(
        token,
        session_secret_key,
        encrypted_secret["text"],
        encrypted_secret["nonce"],
        link_id,
        parent_share_id=parent_id if parent_is_share else None,
        parent_datastore_id=parent_id if not parent_is_share else None,
    )

    item = {
        "id": link_id,
        "name": name,
        "type": "application_password",
        "secret_id": result["secret_id"],
        "secret_key": secret_key,
    }

    if content["application_password_username"]:
        item["description"] = content["application_password_username"]

    # Calculate password_hash - first 5 digits of SHA1 hash in hex notation
    if password:
        password_sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest()
        item["password_hash"] = password_sha1[:5].lower()
    else:
        item["password_hash"] = ""

    folder["items"].append(item)


def create_secret(
    token,
    session_secret_key,
    name,
    username,
    address,
    password,
    folder,
    parent_id,
    parent_is_share=False,
):
    """
    Creates a new secret and adds it to the folder
    Automatically determines whether to create a website_password or application_password
    """
    if is_website_address(address):
        create_website_password_secret(
            token,
            session_secret_key,
            name,
            username,
            address,
            password,
            folder,
            parent_id,
            parent_is_share,
        )
    else:
        create_application_password_secret(
            token,
            session_secret_key,
            name,
            username,
            address,
            password,
            folder,
            parent_id,
            parent_is_share,
        )


def read_csv_file(csv_file_path):
    """
    Reads the CSV file and returns the parsed data
    CSV Format: "safe";"Path";"name";"login";"address";"password"
    """
    entries = []

    if not os.path.exists(csv_file_path):
        print(f"Error: CSV file not found: {csv_file_path}")
        return entries

    with open(csv_file_path, "r", encoding="utf-8") as csvfile:
        # Use semicolon as delimiter
        csv_reader = csv.reader(csvfile, delimiter=";")

        # Skip header row
        next(csv_reader, None)

        for row in csv_reader:
            if len(row) < 6:
                print(f"Warning: Skipping incomplete row: {row}")
                continue

            entry = {
                "safe": row[0].strip().strip('"'),
                "path": row[1].strip().strip('"'),
                "name": row[2].strip().strip('"'),
                "username": row[3].strip().strip('"'),
                "address": row[4].strip().strip('"'),
                "password": row[5].strip().strip('"'),
            }
            entries.append(entry)

    return entries


def group_entries_by_safe(entries):
    """
    Groups CSV entries by the "safe" column
    """
    grouped = {}
    for entry in entries:
        safe = entry["safe"]
        if safe not in grouped:
            grouped[safe] = []
        grouped[safe].append(entry)
    return grouped


def main():
    if len(sys.argv) < 2:
        print("ERROR: No CSV file specified!\n")
        print("Usage: python import_csv_to_datastore.py <csv_file_path> [safe_filter]")
        print("\nArguments:")
        print("  csv_file_path  - Path to the CSV file to import")
        print(
            "  safe_filter    - (Optional) Only import entries for this specific safe"
        )
        print("\nCSV Format (semicolon-separated):")
        print('"safe";"Path";"name of object";"login/username";"address";"password"')
        print("\nExample:")
        print('"myid";"Root";"root account";"root";"192.168.1.1";"secretpass"')
        print(
            '"myid";"Root\\Subfolder";"google";"user@gmail.com";"https://google.com";"pass123"'
        )
        print("\nUsage examples:")
        print(
            "  python import_csv_to_datastore.py passwords.csv           # Import all safes"
        )
        print(
            '  python import_csv_to_datastore.py passwords.csv myid      # Import only "myid" safe'
        )
        sys.exit(1)

    csv_file_path = sys.argv[1]
    safe_filter = sys.argv[2] if len(sys.argv) > 2 else None

    # Read and parse CSV file
    print(f"Reading CSV file: {csv_file_path}")
    entries = read_csv_file(csv_file_path)

    if not entries:
        print("No valid entries found in CSV file")
        sys.exit(1)

    print(f"Found {len(entries)} entries to import")

    # Group entries by safe
    grouped_entries = group_entries_by_safe(entries)
    print(
        f"Entries grouped into {len(grouped_entries)} safe(s): {', '.join(grouped_entries.keys())}"
    )

    # Apply safe filter if specified
    if safe_filter:
        if safe_filter not in grouped_entries:
            print(f"\nERROR: Safe '{safe_filter}' not found in CSV file!")
            print(f"Available safes: {', '.join(grouped_entries.keys())}")
            sys.exit(1)

        print(f"\nFiltering: Only importing safe '{safe_filter}'")
        grouped_entries = {safe_filter: grouped_entries[safe_filter]}

    # Login to API
    print("\nLogging in to Psono...")
    session_private_key, client_login_info = generate_client_login_info()
    json_response = api_login(client_login_info)
    verify_signature(json_response["login_info"], json_response["login_info_signature"])
    decrypted_sever_login_info = decrypt_server_login_info(
        json_response["login_info"],
        json_response["login_info_nonce"],
        json_response["server_session_public_key"],
        session_private_key,
    )

    token = decrypted_sever_login_info["token"]
    session_secret_key = decrypted_sever_login_info["session_secret_key"]
    user_username = decrypted_sever_login_info["user"]["username"]

    # Check API key permissions
    if decrypted_sever_login_info["api_key_restrict_to_secrets"]:
        print(
            "Error: API key is restricted. It should be unrestricted for this operation."
        )
        return
    if not decrypted_sever_login_info["api_key_read"]:
        print("Error: API key doesn't allow read. Please enable read permission.")
        return
    if not decrypted_sever_login_info["api_key_write"]:
        print("Error: API key doesn't allow write. Please enable write permission.")
        return

    user_secret_key = decrypt_with_api_secret_key(
        decrypted_sever_login_info["user"]["secret_key"],
        decrypted_sever_login_info["user"]["secret_key_nonce"],
    )
    user_private_key = decrypt_with_api_secret_key(
        decrypted_sever_login_info["user"]["private_key"],
        decrypted_sever_login_info["user"]["private_key_nonce"],
    )

    # Read datastores
    print(f"Logged in as: {user_username}")
    content = api_read_datastores(token, session_secret_key)

    # Find password datastore
    datastore_content = None
    datastore_id = None
    datastore_secret = None
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
            "Error: No password datastore found. Please create one with the webclient first."
        )
        return

    print(f"Using password datastore: {datastore_id}\n")

    # Process each safe and its entries
    total_imported = 0
    for safe_name, safe_entries in grouped_entries.items():
        print(f"Processing safe: '{safe_name}' ({len(safe_entries)} entries)")

        # Create the top-level safe folder (always new for each import run)
        safe_folder = create_folder(safe_name, datastore_content)

        # Convert the top-level safe folder into a shared folder
        share_id, share_secret_key, share_content = create_shared_folder(
            token,
            session_secret_key,
            safe_folder,
            datastore_content,
            datastore_id,
            user_secret_key,
        )

        # Process each entry in this safe
        for entry in safe_entries:
            print(f"  Creating: {entry['path']}/{entry['name']}")

            # Get or create the folder path within the shared safe root
            target_folder = get_or_create_folder_path(entry["path"], share_content)

            # Create the secret
            create_secret(
                token,
                session_secret_key,
                name=entry["name"],
                username=entry["username"],
                address=entry["address"],
                password=entry["password"],
                folder=target_folder,
                parent_id=share_id,
                parent_is_share=True,
            )
            total_imported += 1

        # Save updated shared folder content
        encrypted_share = encrypt_symmetric(json.dumps(share_content), share_secret_key)
        api_write_share(
            token,
            session_secret_key,
            share_id,
            encrypted_share["text"],
            encrypted_share["nonce"],
        )

        share_share_with_matching_user(
            token,
            session_secret_key,
            safe_name,
            share_id,
            share_secret_key,
            user_private_key,
        )

    # Encrypt and save datastore
    print(f"\nSaving datastore with {total_imported} new entries...")

    # Debug: Show folder structure
    print("\nDebug - Folder structure to be saved:")
    if datastore_content and "folders" in datastore_content:
        for folder in datastore_content["folders"]:
            print(f"  📁 {folder.get('name', 'unnamed')}")
    else:
        print("  (No folders in datastore_content)")

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

    # Logout
    api_logout(token, session_secret_key)

    print(f"\nImport complete! Successfully imported {total_imported} entries.")


if __name__ == "__main__":
    main()
