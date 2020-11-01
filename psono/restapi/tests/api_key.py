from django.urls import reverse
from django.contrib.auth.hashers import make_password
from django.conf import settings

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models

import random
import string
import binascii
import os

class CreateApiKeyTest(APITestCaseExtended):
    """
    Test to create a api key (PUT)
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='90272aaf01a2d525223f192aca069e7f5661b3a0f1b1a91f9b16d493fdf15295',
            is_email_active=True
        )


    def test_create_success(self):
        """
        Tests to create an api key
        """

        url = reverse('api_key')

        data = {
            'title': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        self.assertEqual(models.API_Key.objects.count(), 1)




    def test_create_failure_no_title(self):
        """
        Tests to create an api key without a title
        """

        url = reverse('api_key')

        data = {
            # 'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_secret_key(self):
        """
        Tests to create an api key without a secret key
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            # 'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_secret_key_nonce(self):
        """
        Tests to create an api key without a secret key nonce
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            # 'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_private_key(self):
        """
        Tests to create an api key without a private key
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            # 'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_private_key_nonce(self):
        """
        Tests to create an api key without a private key nonce
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            # 'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_public_key(self):
        """
        Tests to create an api key without a public key
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            # 'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_user_private_key_nonce(self):
        """
        Tests to create an api key without user_private_key_nonce
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            # 'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_user_private_key(self):
        """
        Tests to create an api key without user_private_key_nonce
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            # 'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_user_secret_key_nonce(self):
        """
        Tests to create an api key without user_secret_key_nonce
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            # 'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_user_secret_key(self):
        """
        Tests to create an api key without user_secret_key
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            # 'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_verify_key(self):
        """
        Tests to create an api key without verify_key
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            # 'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_secret_key(self):
        #
        """
        Tests to create an api key with a secret key that is no hex
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123X',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_secret_key_nonce(self):
        """
        Tests to create an api key with a secret key nonce that is no hex
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0FX',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_private_key(self):
        """
        Tests to create an api key with a private key that is no hex
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123X',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_private_key_nonce(self):
        """
        Tests to create an api key with a private key nonce that is no hex
        """

        url = reverse('api_key')

        data = {
            'name': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA88X',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_user_secret_key(self):
        #
        """
        Tests to create an api key with a user secret key that is no hex
        """

        url = reverse('api_key')

        data = {
            'title': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123X',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_user_secret_key_nonce(self):
        """
        Tests to create an api key with a user secret key nonce that is no hex
        """

        url = reverse('api_key')

        data = {
            'title': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA88X',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_user_private_key(self):
        """
        Tests to create an api key with a user private key that is no hex
        """

        url = reverse('api_key')

        data = {
            'title': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123X',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_user_private_key_nonce(self):
        """
        Tests to create an api key with a user_private key nonce that is no hex
        """

        url = reverse('api_key')

        data = {
            'title': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA88X',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_public_key(self):
        """
        Tests to create an api key with a public key nonce that is no hex
        """

        url = reverse('api_key')

        data = {
            'title': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123X',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_verify_key(self):
        """
        Tests to create an api key with a verify key that is no hex
        """

        url = reverse('api_key')

        data = {
            'title': 'Test ApiKey',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
            'user_private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_private_key': 'a123',
            'user_secret_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'user_secret_key': 'a123',
            'verify_key': 'a123X',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class DeleteApiKeyTest(APITestCaseExtended):
    """
    Test to delete an api key (DELETE)
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
            authkey=make_password(self.test_authkey),
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
            authkey=make_password(self.test_authkey2),
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

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


    def test_delete_success(self):
        """
        Tests to delete an api key
        """

        url = reverse('api_key')

        data = {
            'api_key_id': self.test_api_key_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_delete_failure_missing_api_key_id(self):
        """
        Tests to delete an api key
        """

        url = reverse('api_key')

        data = {
            # 'api_key_id': self.test_api_key_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_belongs_to_other_user(self):
        """
        Tests to delete an api key that belongs to another user
        """

        url = reverse('api_key')

        data = {
            'api_key_id': self.test_api_key_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_not_exist(self):
        """
        Tests to delete an api key that does not exist
        """

        url = reverse('api_key')

        data = {
            'api_key_id': 'b654edd8-1ff3-4512-9b83-edfc89bb8226',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class ReadApiKeyTest(APITestCaseExtended):
    """
    Test to read an api key (GET)
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='90272aaf01a2d525223f192aca069e7f5661b3a0f1b1a91f9b16d493fdf15295',
            is_email_active=True
        )

        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt2 = "b"
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
            authkey=make_password(self.test_authkey2),
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

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


    def test_read_api_keys_success(self):
        """
        Tests to read all api_keys
        """

        url = reverse('api_key')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get('api_keys', False))
        self.assertEqual(len(response.data.get('api_keys')), 1)

        api_keys = response.data.get('api_keys')
        api_key = api_keys[0]

        self.assertEqual(api_key.get('id'), self.test_api_key_obj.id)
        self.assertEqual(api_key.get('title'), self.test_api_key_obj.title)
        self.assertEqual(api_key.get('read'), self.test_api_key_obj.read)
        self.assertEqual(api_key.get('write'), self.test_api_key_obj.write)
        self.assertEqual(api_key.get('restrict_to_secrets'), self.test_api_key_obj.restrict_to_secrets)
        self.assertEqual(api_key.get('allow_insecure_access'), self.test_api_key_obj.allow_insecure_access)
        self.assertEqual(api_key.get('active'), self.test_api_key_obj.active)


    def test_read_api_keys_success_without_permission(self):
        """
        Tests to read all api_keys with a user that has no permissions
        """

        url = reverse('api_key')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data.get('api_keys', True)) # Empty List
        self.assertEqual(len(response.data.get('api_keys')), 0)


    def test_read_api_key_success(self):
        """
        Tests to read a specific api_key successful
        """

        url = reverse('api_key', kwargs={'api_key_id': self.test_api_key_obj.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('id'), self.test_api_key_obj.id)
        self.assertEqual(response.data.get('title'), self.test_api_key_obj.title)
        self.assertEqual(response.data.get('public_key'), self.test_api_key_obj.public_key)
        self.assertEqual(response.data.get('secret_key'), self.test_api_key_obj.secret_key)
        self.assertEqual(response.data.get('secret_key_nonce'), self.test_api_key_obj.secret_key_nonce)
        self.assertEqual(response.data.get('private_key'), self.test_api_key_obj.private_key)
        self.assertEqual(response.data.get('private_key_nonce'), self.test_api_key_obj.private_key_nonce)
        self.assertEqual(response.data.get('read'), self.test_api_key_obj.read)
        self.assertEqual(response.data.get('write'), self.test_api_key_obj.write)
        self.assertEqual(response.data.get('restrict_to_secrets'), self.test_api_key_obj.restrict_to_secrets)
        self.assertEqual(response.data.get('allow_insecure_access'), self.test_api_key_obj.allow_insecure_access)
        self.assertEqual(response.data.get('active'), True)



    def test_read_api_key_failure_not_exist(self):
        """
        Tests to read a specific api_key that does not exist
        """

        url = reverse('api_key', kwargs={'api_key_id': '212dbbe0-7d1c-4136-b514-6c9d374d579c'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



    def test_read_api_key_failure_no_permission(self):
        """
        Tests to read a specific api_key with a user that does not own the api key
        """

        url = reverse('api_key', kwargs={'api_key_id': self.test_api_key_obj.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UpdateApiKeyTest(APITestCaseExtended):
    """
    Test to update an api key (POST)
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='90272aaf01a2d525223f192aca069e7f5661b3a0f1b1a91f9b16d493fdf15295',
            is_email_active=True
        )

        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt2 = "b"
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
            authkey=make_password(self.test_authkey2),
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

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

        self.token = models.Token.objects.create(
            key=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            user=self.test_user_obj,
            api_key=self.test_api_key_obj,
            write=self.test_api_key_obj.write,
            read=self.test_api_key_obj.read,
        )


    def test_update_api_keys_success(self):
        """
        Tests to update an api key
        """

        url = reverse('api_key')

        data = {
            'api_key_id': self.test_api_key_obj.id,
            'title': 'New Title',
            'read': False,
            'write': False,
            'restrict_to_secrets': False,
            'allow_insecure_access': False,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        api_key = models.API_Key.objects.get(pk=self.test_api_key_obj.id)

        self.assertEqual(api_key.title, data.get('title'))
        self.assertEqual(api_key.read, data.get('read'))
        self.assertEqual(api_key.write, data.get('write'))
        self.assertEqual(api_key.restrict_to_secrets, data.get('restrict_to_secrets'))
        self.assertEqual(api_key.allow_insecure_access, data.get('allow_insecure_access'))

        tokens = api_key.tokens.all()

        self.assertEqual(len(tokens), 1)

        token = tokens[0]

        self.assertEqual(token.read, data.get('read'))
        self.assertEqual(token.write, data.get('write'))


    # def test_update_api_keys_failure_with_no_actual_data(self):
    #     """
    #     Tests to update an api key that results in a failure as no actual data is provided
    #     """
    #
    #     url = reverse('api_key')
    #
    #     data = {
    #         'api_key_id': self.test_api_key_obj.id,
    #     }
    #
    #     self.client.force_authenticate(user=self.test_user_obj)
    #     response = self.client.post(url, data)
    #
    #     self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_api_keys_failure_no_permission(self):
        """
        Tests to update an api key with no permissions
        """

        url = reverse('api_key')

        data = {
            'api_key_id': self.test_api_key_obj.id,
            'title': 'New Title',
            'read': False,
            'write': False,
            'restrict_to_secrets': False,
            'allow_insecure_access': False,
        }

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_api_keys_failure_not_exist(self):
        """
        Tests to update an api key which does not not exist
        """

        url = reverse('api_key')

        data = {
            'api_key_id': 'd7e600a6-3764-43c0-81fc-2401e6ccd6c2',
            'title': 'New Title',
            'read': False,
            'write': False,
            'restrict_to_secrets': False,
            'allow_insecure_access': False,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

