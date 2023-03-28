"""
A small demo script that shows how to access a specific secret without a session (restricted API key)
"""
import requests
import json
import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.utils

api_key_id = '6a38b651-412d-4d66-a4b3-730b016f8635'
api_key_private_key = 'fc1a9cc5e6ff6efd2abe7b8a9625264ac504a348de16e11086821f9ba48204b9'
api_key_secret_key = '103115fbb712ce89940a2028cc50a3646e9a680ba6b70068a8a424c2bfaadc15'
server_url = 'http://browserplugins.chickahoona.com/server'
server_public_key = '02da2ad857321d701d754a7e60d0a147cdbc400ff4465e1f57bc2d9fbfeddf0b'
server_signature = '4ce9e761e1d458fe18af577c50eb8249a0de535c9bd6b7a97885c331b46dcbd1'


SSL_VERIFY = False


def api_request(method, endpoint, data = None):

    headers = {'content-type': 'application/json'}

    r = requests.request(method, server_url + endpoint, data=data, headers=headers, verify=SSL_VERIFY)

    return r.json()

def api_read_secret(secret_id):

    method = 'POST'
    endpoint = '/api-key-access/secret/'

    data = json.dumps({
        'api_key_id': api_key_id,
        'secret_id': secret_id,
    })

    encrypted_secret = api_request(method, endpoint, data)

    # decrypt step 1: Decryption of the encryption key
    crypto_box = nacl.secret.SecretBox(api_key_secret_key, encoder=nacl.encoding.HexEncoder)
    encryption_key = crypto_box.decrypt(nacl.encoding.HexEncoder.decode(encrypted_secret['secret_key']),
                                        nacl.encoding.HexEncoder.decode(encrypted_secret['secret_key_nonce']))

    # decrypt step 2: Decryption of the secret
    crypto_box = nacl.secret.SecretBox(encryption_key, encoder=nacl.encoding.HexEncoder)
    decrypted_secret = crypto_box.decrypt(nacl.encoding.HexEncoder.decode(encrypted_secret['data']),
                                          nacl.encoding.HexEncoder.decode(encrypted_secret['data_nonce']))

    return json.loads(decrypted_secret), encryption_key

def api_write_secret(secret_id, encryption_key, decrypted_secret):

    # Encrypt the secret with a random nonce
    crypto_box = nacl.secret.SecretBox(encryption_key, encoder=nacl.encoding.HexEncoder)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted_secret_full = crypto_box.encrypt(json.dumps(decrypted_secret).encode("utf-8"), nonce)
    encrypted_secret = encrypted_secret_full[len(nonce):]

    method = 'PUT'
    endpoint = '/api-key-access/secret/'

    data = json.dumps({
        'api_key_id': api_key_id,
        'secret_id': secret_id,
        'data': nacl.encoding.HexEncoder.encode(encrypted_secret).decode(),
        'data_nonce': nacl.encoding.HexEncoder.encode(nonce).decode()
    })

    api_request(method, endpoint, data)

def api_inspect():
    """
    Inspects the API key. Will return a list of allowed secrets if its a restricted API key.

    :return:
    :rtype:
    """

    method = 'POST'
    endpoint = '/api-key-access/inspect/'

    data = json.dumps({
        'api_key_id': api_key_id,
    })

    api_inspect_result = api_request(method, endpoint, data)

    return api_inspect_result

def main():

    secret_id = '4620cff5-f22b-4466-afb7-7fec94411243'

    # We can inspect the API key like this:
    # api_inspect_result = api_inspect()
    # print(api_inspect_result)
    # {
    #     'allow_insecure_access': False,
    #     'restrict_to_secrets': True,
    #     'read': True,
    #     'write': True,
    #     'api_key_secrets': [{
    #         'secret_id': '4620cff5-f22b-4466-afb7-7fec94411243'
    #     }, {
    #         'secret_id': '345d8909-fae3-446a-8b97-9b6a9dbf0851'
    #     }
    #     ]
    # }

    # We can read the secret like this:
    # (Requires read permission)
    decrypted_secret, encryption_key = api_read_secret(secret_id)
    print(decrypted_secret)
    # {'totp_code': 'JBSWY3DPEHPK3PXP', 'totp_title': 'demo'}

    # We can update the secret like this:
    # (Requires write permission)
    decrypted_secret['totp_title'] = 'new title'
    api_write_secret(secret_id, encryption_key, decrypted_secret)


if __name__ == '__main__':
    main()