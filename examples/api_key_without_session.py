import requests
import json
import nacl.encoding
import nacl.signing
import nacl.secret

api_key_id = '747b0fb0-1f25-4c45-af94-50d487af15f1'
api_key_private_key = 'e6e71d12eaade92994a915fa5ecfd54223e53d72e02cfc73bc2b968a061eea7e'
api_key_secret_key = '1a74783f7429b95b64483f910019d3559f7f1da429fcc1a2e187880e938d611c'
server_url = 'https://browserplugins.chickahoona.com/server'
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

    return json.loads(decrypted_secret)

def main():

    secret_id = 'c81d0cff-65f9-4f81-9815-dbe2850331c9'

    decrypted_secret = api_read_secret(secret_id)

    print(decrypted_secret)


if __name__ == '__main__':
    main()