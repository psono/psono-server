from django.core.urlresolvers import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from ..authentication import TokenAuthentication
from rest_framework import status

from restapi import models

from .base import APITestCaseExtended

import random
import string

import hashlib




class SessionTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "asd"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "abc"
        self.test_username = "test@psono.pw"
        self.test_username2 = "test2@psono.pw"
        self.test_password = "myPassword"
        self.test_authkey = "c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
                            "123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
        self.test_public_key = "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        self.test_secret_key = "a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
        self.test_secret_key_enc = "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
                                   "996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
                                   "571a48eb"
        self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce2 = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"

        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='3e7a12fcb7171c917005ef8110503ffbb85764163dbb567ef481e72a37f352a7',
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='f3c0a6788364ab164d574b655ac2a90b8124d3a20fd341c38a24566188390d01',
            is_email_active=True
        )

        self.session_secret_key = hashlib.sha256(settings.DB_SECRET.encode('utf-8')).hexdigest()
        self.token_u1_1 = ''.join(random.choice(string.ascii_lowercase) for _ in range(32))
        models.Token.objects.create(
            key=TokenAuthentication.user_token_to_token_hash(self.token_u1_1),
            user=self.test_user_obj,
            secret_key=self.session_secret_key,
            active=True,
            device_description='Device 1',
        )

        self.token_u1_2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(32))
        models.Token.objects.create(
            key=TokenAuthentication.user_token_to_token_hash(self.token_u1_2),
            user=self.test_user_obj,
            secret_key=self.session_secret_key,
            active=True,
            device_description='Device 2',
        )

        self.token_u2_1 = ''.join(random.choice(string.ascii_lowercase) for _ in range(32))
        models.Token.objects.create(
            key=TokenAuthentication.user_token_to_token_hash(self.token_u2_1),
            user=self.test_user2_obj,
            secret_key=self.session_secret_key,
            active=True,
            device_description='Device 3',
        )


    def test_list_datastores_without_credentials(self):
        """
        Tests if someone gets datastores without credentials
        """

        url = reverse('authentication_session')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_u1_1)
        response = self.client.get(url, data, user=self.test_user_obj)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get('sessions', False), False)

        sessions = response.data.get('sessions', [])
        self.assertEqual(len(sessions), 2)

        found_device1 = False
        found_device2 = False
        for session in response.data.get('sessions', []):
            if session['device_description'] == "Device 1":
                found_device1 = True
                self.assertEqual(session['current_session'], True)
                continue
            if session['device_description'] == "Device 2":
                found_device2 = True
                self.assertEqual(session['current_session'], False)
                continue

        self.assertTrue(found_device1)
        self.assertTrue(found_device2)






