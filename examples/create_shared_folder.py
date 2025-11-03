"""
A demo script that shows how to create a new shared folder using API keys (unrestricted API key)

This example demonstrates the process of:
1. Authenticating with an API key
2. Reading the user's datastore
3. Creating a new folder in the datastore
4. Converting that folder into a shared folder by:
   - Generating a new secret key for the share
   - Encrypting the folder content with the new secret key
   - Calling the backend to create a share
   - Storing the share_id and share_secret_key in the datastore
5. Updating the datastore with the new shared folder reference
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

api_key_id = 'e1cd9c08-4887-4b06-a26d-c92b1e84f49e'
api_key_private_key = '0bbc18ac5d82ffabe324722ade66d99378c7772eef727e8e255e38ad2ab9f50c'
api_key_secret_key = '04ab9b23de0f710e2c521fb1fbb77802dbd9f1586c31fd454b0497f0aa94acb4'
server_url = 'https://psonoclient.chickahoona.com/server'
server_public_key = '02da2ad857321d701d754a7e60d0a147cdbc400ff4465e1f57bc2d9fbfeddf0b'
server_signature = '4ce9e761e1d458fe18af577c50eb8249a0de535c9bd6b7a97885c331b46dcbd1'

SSL_VERIFY = False

def get_device_description():
    """
    This info is later shown in the "Open sessions" overview in the client. Should be something so the user knows where
    this session is coming from.

    :return:
    :rtype:
    """
    return 'Console Client ' + socket.gethostname()

def generate_client_login_info():
    """
    Generates and signs the login info
    Returns a tuple of the session private key and the login info

    :return:
    :rtype:
    """

    box = PrivateKey.generate()
    session_private_key = box.encode(encoder=nacl.encoding.HexEncoder).decode()
    session_public_key = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

    info = {
        'api_key_id': api_key_id,
        'session_public_key': session_public_key,
        'device_description': get_device_description(),
    }

    info = json.dumps(info)

    signing_box = nacl.signing.SigningKey(api_key_private_key, encoder=nacl.encoding.HexEncoder)

    # The first 128 chars (512 bits or 64 bytes) are the actual signature, the rest the binary encoded info
    signed = signing_box.sign(info.encode())
    signature = binascii.hexlify(signed.signature)

    return session_private_key, {
        'info': info,
        'signature': signature.decode(),
    }

def decrypt_server_login_info(login_info_hex, login_info_nonce_hex, session_public_key, session_private_key):
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

    crypto_box = Box(PrivateKey(session_private_key, encoder=nacl.encoding.HexEncoder),
                     PublicKey(session_public_key, encoder=nacl.encoding.HexEncoder))

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

    verify_key = nacl.signing.VerifyKey(server_signature, encoder=nacl.encoding.HexEncoder)

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
    nonce = nacl.encoding.HexEncoder.decode(nonce_hex)

    secret_box = nacl.secret.SecretBox(secret, encoder=nacl.encoding.HexEncoder)

    return secret_box.decrypt(text, nonce)


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
    text = encrypted[len(nonce):]

    # convert nonce and encrypted msg to hex
    nonce_hex = nacl.encoding.HexEncoder.encode(nonce).decode()
    text_hex = nacl.encoding.HexEncoder.encode(text).decode()

    return {'text': text_hex, 'nonce': nonce_hex}

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


def api_request(method, endpoint, data = None, token = None, session_secret_key = None):

    if token:
        headers = {'content-type': 'application/json', 'authorization': 'Token ' + token}
    else:
        headers = {'content-type': 'application/json'}

    if session_secret_key and data:
        data = json.dumps(encrypt_symmetric(data, session_secret_key))

    r = requests.request(method, server_url + endpoint, data=data, headers=headers, verify=SSL_VERIFY)

    if not session_secret_key:
        return r.json()
    else:
        encrypted_content = r.json()
        decrypted_content = decrypt_symmetric(encrypted_content['text'], encrypted_content['nonce'], session_secret_key)
        return json.loads(decrypted_content)


def api_login(client_login_info):
    """
    API Request: Sends the actual login

    :param client_login_info:
    :type client_login_info:

    :return:
    :rtype:
    """

    method = 'POST'
    endpoint = '/api-key/login/'
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

    method = 'GET'
    endpoint = '/datastore/'

    return api_request(method, endpoint, token=token, session_secret_key=session_secret_key)


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

    method = 'POST'
    endpoint = '/authentication/logout/'

    return api_request(method, endpoint, token=token, session_secret_key=session_secret_key)


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

    method = 'GET'
    endpoint = '/datastore/' + datastore_id + '/'

    return api_request(method, endpoint, token=token, session_secret_key=session_secret_key)


def api_write_datastore(token, session_secret_key, datastore_id, encrypted_data, encrypted_data_nonce):
    """
    Updates a datastore

    :param token:
    :type token:
    :param session_secret_key:
    :type session_secret_key:
    :param datastore_id:
    :type datastore_id:
    :param encrypted_data:
    :type encrypted_data:
    :param encrypted_data_nonce:
    :type encrypted_data_nonce:
    :return:
    :rtype:
    """

    method = 'POST'
    endpoint = '/datastore/'
    data = json.dumps({
        'datastore_id': datastore_id,
        'data': encrypted_data,
        'data_nonce': encrypted_data_nonce,
    })

    return api_request(method, endpoint, data=data, token=token, session_secret_key=session_secret_key)


def api_create_share(token, session_secret_key, encrypted_data, encrypted_data_nonce, encrypted_key, encrypted_key_nonce, parent_datastore_id, link_id):
    """
    Creates a new share

    :param token:
    :param session_secret_key:
    :param encrypted_data:
    :param encrypted_data_nonce:
    :param encrypted_key:
    :param encrypted_key_nonce:
    :param parent_datastore_id:
    :param link_id:
    :return:
    """

    method = 'POST'
    endpoint = '/share/'
    data = json.dumps({
        'data': encrypted_data,
        'data_nonce': encrypted_data_nonce,
        'key': encrypted_key,
        'key_nonce': encrypted_key_nonce,
        'key_type': 'symmetric',
        'parent_datastore_id': parent_datastore_id,
        'link_id': link_id,
    })

    return api_request(method, endpoint, data=data, token=token, session_secret_key=session_secret_key)


def create_folder(folder_name, datastore_content):
    """
    Creates a new folder in the datastore

    :param folder_name:
    :param datastore_content:
    :return:
    """
    if 'folders' not in datastore_content:
        datastore_content['folders'] = []

    folder = {
        'id': str(uuid.uuid4()),
        'name': folder_name,
    }

    datastore_content['folders'].append(folder)

    return folder


def convert_folder_to_share(token, session_secret_key, folder, datastore_content, datastore_id, user_secret_key):
    """
    Converts a regular folder into a shared folder by:
    1. Generating a new secret key for the share
    2. Encrypting the folder content with the new secret key
    3. Creating a share on the backend
    4. Adding share_id and share_secret_key to the folder object
    5. Updating the share_index in the datastore

    :param token:
    :param session_secret_key:
    :param folder:
    :param datastore_content:
    :param datastore_id:
    :param user_secret_key:
    :return: tuple of (share_id, share_secret_key)
    """

    # Step 1: Generate a new secret key for the share (32 bytes = 256 bits)
    share_secret_key = nacl.encoding.HexEncoder.encode(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)).decode()

    # Step 2: Prepare the folder content for the share
    # Remove the folder id since it's stored in the datastore, not in the share
    share_content = {
        'name': folder['name'],
    }

    # Copy over any existing items or subfolders
    # NOTE: If the folder contains items (secrets), you would need to inform the server
    # about the "move" of those items from the datastore to the share by calling:
    # - POST /secret/link/ for each secret to update its parent_share_id
    # - POST /file/link/ for each file to update its parent_share_id
    # This example assumes an empty folder for simplicity.
    if 'items' in folder:
        share_content['items'] = folder['items']
    if 'folders' in folder:
        share_content['folders'] = folder['folders']

    # Step 3: Encrypt the share content with the new share secret key
    encrypted_share = encrypt_symmetric(json.dumps(share_content), share_secret_key)

    # Step 4: Encrypt the share secret key with the user's secret key (so it can be stored in the datastore)
    encrypted_share_key = encrypt_symmetric(share_secret_key, user_secret_key)

    # Step 5: Create a link_id for the share (this links the folder in the datastore to the share)
    link_id = folder['id']

    # Step 6: Call the backend to create the share
    result = api_create_share(
        token,
        session_secret_key,
        encrypted_share['text'],
        encrypted_share['nonce'],
        encrypted_share_key['text'],
        encrypted_share_key['nonce'],
        datastore_id,
        link_id
    )

    share_id = result['share_id']

    # Step 7: Update the folder object with share information
    folder['share_id'] = share_id
    folder['share_secret_key'] = share_secret_key

    # Step 8: Update the share_index in the datastore
    # The share_index is a dictionary that maps share_ids to their metadata (paths and secret_key)
    # This allows the client to efficiently locate and decrypt shares within the datastore
    if 'share_index' not in datastore_content:
        datastore_content['share_index'] = {}

    # Add the new share to the share_index
    # The path contains the folder ID because the share is located at this folder in the datastore
    # If the folder were nested, the path would be [parent_folder_id, child_folder_id, ...]
    datastore_content['share_index'][share_id] = {
        'paths': [[folder['id']]],  # Array of paths where this share appears (list of folder IDs leading to the share)
        'secret_key': share_secret_key,  # The share's secret key for decryption
    }

    print(f"Created shared folder '{folder['name']}' with share_id: {share_id}")

    return share_id, share_secret_key


def main():
    # 1. Generate the login info including the private key for PFS
    session_private_key, client_login_info = generate_client_login_info()

    # 2. Send the login request and handle eventual exceptions, problems and so on ...
    json_response = api_login(client_login_info)

    # 3. Verify the signature in order to proof that we are really communicating with the server
    # (or someone who is in the posession of the servers private key :D)
    verify_signature(json_response['login_info'], json_response['login_info_signature'])

    # 4. Decrypt the actual login info with the token and session_secret_key for the transport encryption
    decrypted_sever_login_info = decrypt_server_login_info(json_response['login_info'], json_response['login_info_nonce'], json_response['server_session_public_key'], session_private_key)

    token = decrypted_sever_login_info['token'] # That is the token that we have to send always as header
    session_secret_key = decrypted_sever_login_info['session_secret_key'] # that is the symmetric secret for the transport encryption
    user_username = decrypted_sever_login_info['user']['username'] # The username
    user_public_key = decrypted_sever_login_info['user']['public_key'] # The user's public key

    if decrypted_sever_login_info['api_key_restrict_to_secrets']:
        print("api key is restricted. it should only be used to read specific secrets")
        return
    if not decrypted_sever_login_info['api_key_read']:
        print("api key doesn't allow read. Please allow read first")
        return

    if not decrypted_sever_login_info['api_key_write']:
        print("api key doesn't allow write. Please allow write first")
        return

    # if the api key is unrestricted then the request will also return the encrypted secret and private key of the user, symmetric encrypted with the api secret key
    user_private_key = decrypt_with_api_secret_key(decrypted_sever_login_info['user']['private_key'], decrypted_sever_login_info['user']['private_key_nonce']) # The user's private key
    user_secret_key = decrypt_with_api_secret_key(decrypted_sever_login_info['user']['secret_key'], decrypted_sever_login_info['user']['secret_key_nonce']) # The user's secret key

    # 5. Now we can start actual reading the datastore and secrets e.g. to read the datastore:
    content = api_read_datastores(token, session_secret_key)

    # 6. Read content of the first password datastore
    datastore_content = None
    datastore_id = None
    datastore_secret = None
    for datastore in content['datastores']:
        if datastore['type'] != 'password':
            continue
        datastore_id = datastore['id']
        datastore_read_result = api_read_datastore(token, session_secret_key, datastore['id'])
        datastore_secret = decrypt_symmetric(datastore_read_result['secret_key'], datastore_read_result['secret_key_nonce'], user_secret_key)
        datastore_content = json.loads(decrypt_symmetric(datastore_read_result['data'], datastore_read_result['data_nonce'], datastore_secret))
        break

    if datastore_id is None:
        print("No password datastore yet found, please create one for the user first with the webclient.")
        return

    # 7. Create a new folder
    folder_name = 'My New Shared Folder'
    folder = create_folder(folder_name, datastore_content)

    print(f"Created folder '{folder_name}' with id: {folder['id']}")

    # 8. Convert the folder to a shared folder
    share_id, share_secret_key = convert_folder_to_share(
        token,
        session_secret_key,
        folder,
        datastore_content,
        datastore_id,
        user_secret_key
    )

    # 9. Encrypt and save the updated datastore (which now contains the shared folder reference)
    encrypted_datastore = encrypt_symmetric(json.dumps(datastore_content), datastore_secret)
    api_write_datastore(token, session_secret_key, datastore_id, encrypted_datastore['text'], encrypted_datastore['nonce'])

    print(f"\nSuccess! Shared folder created:")
    print(f"  - Folder name: {folder_name}")
    print(f"  - Folder ID: {folder['id']}")
    print(f"  - Share ID: {share_id}")
    print(f"  - Share secret key: {share_secret_key}")
    print(f"\nThe shared folder is now stored in the user's datastore and can be shared with other users.")

    # 10. Logout
    api_logout(token, session_secret_key)


if __name__ == '__main__':
    main()
