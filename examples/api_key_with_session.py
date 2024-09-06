"""
A small demo script that shows how to access the datastore with a session (unrestricted API key) and modify a secret
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

api_key_id = '13250ce0-a98f-4e31-83a7-a181fa785baa'
api_key_private_key = '318c9e10c4081d0d38df376f93ebe0b9fd9d96871496911b9f39614312a1fd55'
api_key_secret_key = '45bd4658c4018f6b81b26b9a6757f4980c1edfc41b7d811aa8e8e78f3851fef7'
server_url = 'https://browserplugins.chickahoona.com/server'
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

    method = 'GET'
    endpoint = '/secret/' + secret_id + '/'

    return api_request(method, endpoint, token=token, session_secret_key=session_secret_key)

def api_update_secret(token, session_secret_key, secret_id, data, data_nonce):
    """
    Updates the content of a specific secret

    :param token:
    :type token:
    :param session_secret_key:
    :type session_secret_key:
    :param secret_id:
    :type secret_id:
    :param data:
    :type data:
    :param data_nonce:
    :type data_nonce:
    :return:
    :rtype:
    """

    method = 'POST'
    endpoint = '/secret/'


    data = json.dumps({
        'secret_id': secret_id,
        'data': data,
        'data_nonce': data_nonce
    })

    return api_request(method, endpoint, data=data, token=token, session_secret_key=session_secret_key)

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

    # if the api key is unrestricted then the request will also return the encrypted secret and private key of the user, symmetric encrypted with the api secret key
    user_private_key = decrypt_with_api_secret_key(decrypted_sever_login_info['user']['private_key'], decrypted_sever_login_info['user']['private_key_nonce']) # The user's private key
    user_secret_key = decrypt_with_api_secret_key(decrypted_sever_login_info['user']['secret_key'], decrypted_sever_login_info['user']['secret_key_nonce']) # The user's secret key

    # 5. Now we can start actual reading the datastore and secrets e.g. to read the datastore:
    content = api_read_datastores(token, session_secret_key)

    datastore_secret = None

    # 6. Read content of all password datastores
    for datastore in content['datastores']:
        if datastore['type'] != 'password':
            continue
        datastore_read_result = api_read_datastore(token, session_secret_key, datastore['id'])
        datastore_secret = decrypt_symmetric(datastore_read_result['secret_key'], datastore_read_result['secret_key_nonce'], user_secret_key)
        datastore_content = json.loads(decrypt_symmetric(datastore_read_result['data'], datastore_read_result['data_nonce'], datastore_secret))
        # print(datastore_content)
        # {
        #     "datastore_id": "73229adf-14bc-4370-8e8c-755732322558",
        #     "items": [{
        #         "id": "bef4212a-a169-4be8-8521-4da899c3f507",
        #         "type": "website_password",
        #         "urlfilter": "example.com",
        #         "name": "A website Password",
        #         "secret_id": "6562a9bf-b8f2-47ba-8b07-4a3040af0c86",
        #         "secret_key": "64f629843d479ebab32e69be10ffff3cfaf64d69a0d6ea785611bbce7cb66052"
        #     }
        #     ],
        #     "folders": [{
        #         "id": "7d6a3eec-0ff6-4a67-b7f0-b886fa771408",
        #         "name": "A folder",
        #         "folders": [{
        #             "id": "e360e080-5cf0-4e59-8db8-c06aa66ffed3",
        #             "name": "A subfolder",
        #             "items": [{
        #                 "id": "21e1e13c-257a-4537-8cd2-35f123a42192",
        #                 "type": "note",
        #                 "name": "A note in subfolder",
        #                 "secret_id": "10d14e24-a05e-4428-b245-35cb0fdc7256",
        #                 "secret_key": "26060d92a1e150e8810160551c5b23b1ab02c8fa3563c77e9544a0b145eee63d"
        #             }
        #             ]
        #         }
        #         ]
        #     }
        #     ]
        # }

        # search the datastore for the secret that you would like to have, either by the urlfilter, id, or name...
        # for the purpose of this example we will pick the first website_password that is in the root of the datastore
        if 'items' in datastore_content:
            for item in datastore_content['items']:
                if item['type'] == 'website_password':
                    datastore_secret = item


    if datastore_secret is None:
        print("No website password found in datastore. This demo script expects a website password in the root of the datastore")
        return


    # 7. Read a secret
    secret_read_result = api_read_secret(token, session_secret_key, datastore_secret['secret_id'])
    secret_content = json.loads(decrypt_symmetric(secret_read_result['data'], secret_read_result['data_nonce'], datastore_secret['secret_key']))
    # print(secret_content)
    # {
    #     'website_password_url_filter': 'example.com',
    #     'website_password_password': 'aPassWord',
    #     'website_password_username': 'something@example.com',
    #     'website_password_url': 'https://example.com',
    #     'website_password_title': 'A website Password'
    # }

    # 9. Update Secret
    # You can update the secret now. Please take note that this updates only the secret. If you'd update the title
    # and want that the title is shown correctly in the datastore too, you will have to update the datastore accordingly.
    secret_content['website_password_password'] = 'Any value'
    encrypted_secret = encrypt_symmetric(json.dumps(secret_content), datastore_secret['secret_key'])
    api_update_secret(token, session_secret_key, datastore_secret['secret_id'], encrypted_secret['text'], encrypted_secret['nonce'])

    # 9. Logout
    api_logout(token, session_secret_key)

if __name__ == '__main__':
    main()