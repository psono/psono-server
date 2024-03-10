from django.urls import reverse
from django.conf import settings

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models

import random
import string
import binascii
import json
import os

import nacl.secret
import nacl.utils
import nacl.encoding

class CreateApiKeyAccessInspectTest(APITestCaseExtended):
    """
    Test to inspect an an api key (POST)
    """
    def setUp(self):

        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_password = "myPassword"
        self.test_authkey = "c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
                            "123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
        self.test_public_key = "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        self.test_secret_key = "a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
        self.test_secret_key_enc = "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
                                   "996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
                                   "571a48eb"
        self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"

        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='90272aaf01a2d525223f192aca069e7f5661b3a0f1b1a91f9b16d493fdf15295',
            is_email_active=True
        )

        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt2 = 'a'
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey2 = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key2 = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key2 = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key2 = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce2 = 'a67fef1ff29eb8f866feaccad336fc6311fa4c71bc183b14c8fceff7416add99'
        self.test_user_obj2 = models.User.objects.create(
            username=self.test_username2,
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            authkey="abc",
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

        self.test_datastore1_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data=b"12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )


        secret_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        secret_key_hex = nacl.encoding.HexEncoder.encode(secret_key)
        self.box = nacl.secret.SecretBox(secret_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

        self.secret_data = json.dumps({
            'secret_content': 'some_variable',
            'secret_content_json': {
                'sub_secret_content': 'some_variable_1'
            },
            'secret_content_nested_json': json.dumps({
                'sub_secret_content_nested': 'some_variable_2'
            })
        })
        encrypted = self.box.encrypt(self.secret_data.encode(), nonce)

        self.test_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=nacl.encoding.HexEncoder.encode(encrypted.ciphertext),
            data_nonce=nacl.encoding.HexEncoder.encode(nonce).decode(),
            type="dummy"
        )

        self.secret_link_obj = models.Secret_Link.objects.create(
            link_id = '0493017f-47b0-446e-9a41-6533721ade71',
            secret_id = self.test_secret_obj.id,
            parent_datastore_id = self.test_datastore1_obj.id,
            parent_share_id = None
        )

        api_key_secret_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.api_key_secret_key_hex = nacl.encoding.HexEncoder.encode(api_key_secret_key)
        box = nacl.secret.SecretBox(self.api_key_secret_key_hex, encoder=nacl.encoding.HexEncoder)

        self.test_api_key_obj = models.API_Key.objects.create(
            user = self.test_user_obj,
            title = 'Test Title',
            public_key = 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            private_key = 'a123',
            private_key_nonce = 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            secret_key = 'a123',
            secret_key_nonce = 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            user_private_key = 'a123',
            user_private_key_nonce = 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            user_secret_key = 'a123',
            user_secret_key_nonce = 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            verify_key = 'a123',
            read = True,
            write = True,
            restrict_to_secrets = True,
            allow_insecure_access = True,
        )

        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(secret_key_hex, nonce)

        self.test_api_key_secret_obj = models.API_Key_Secret.objects.create(
            api_key=self.test_api_key_obj,
            secret=self.test_secret_obj,
            title='a123',
            title_nonce='B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            secret_key=nacl.encoding.HexEncoder.encode(encrypted.ciphertext).decode(),
            secret_key_nonce=nacl.encoding.HexEncoder.encode(nonce).decode(),
        )


    def test_get(self):
        """
        Tests GET on api_key_access_secret
        """

        url = reverse('api_key_access_inspect')

        data = {
        }

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_put(self):
        """
        Tests PUT on api_key_access_secret
        """

        url = reverse('api_key_access_inspect')

        data = {
        }

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_delete(self):
        """
        Tests DELETE on api_key_access_secret
        """

        url = reverse('api_key_access_inspect')

        data = {
        }

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_post(self):
        """
        Tests POST on api_key_access_secret
        """

        url = reverse('api_key_access_inspect')

        data = {
            'api_key_id': self.test_api_key_obj.id,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


        data = json.loads(response.data)

        self.assertEqual(data.get('allow_insecure_access', not self.test_api_key_obj.allow_insecure_access), self.test_api_key_obj.allow_insecure_access)
        self.assertEqual(data.get('restrict_to_secrets', not self.test_api_key_obj.restrict_to_secrets), self.test_api_key_obj.restrict_to_secrets)
        self.assertEqual(data.get('read', not self.test_api_key_obj.read), self.test_api_key_obj.read)
        self.assertEqual(data.get('write', not self.test_api_key_obj.write), self.test_api_key_obj.write)
        self.assertEqual(len(data.get('api_key_secrets', [])), 1)
        self.assertEqual(data['api_key_secrets'][0]['secret_id'], str(self.test_secret_obj.id))
        self.assertEqual(data['api_key_secrets'][0]['write_date'], self.test_secret_obj.write_date.isoformat())