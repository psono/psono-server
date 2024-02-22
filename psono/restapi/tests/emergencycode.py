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

class CreateEmergencyCodeTest(APITestCaseExtended):
    """
    Test to create a emergency code (PUT)
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
        Tests to create an emergency code
        """

        url = reverse('emergencycode')

        data = {
            'description': 'Some Description',
            'activation_delay': 3600,
            'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'emergency_data': 'a123',
            'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        self.assertEqual(models.Emergency_Code.objects.count(), 1)


    def test_create_failure_no_description(self):
        """
        Tests to create an emergency code without description
        """

        url = reverse('emergencycode')

        data = {
            # 'description': 'Some Description',
            'activation_delay': 3600,
            'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'emergency_data': 'a123',
            'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_activation_delay(self):
        """
        Tests to create an emergency code without activation delay
        """

        url = reverse('emergencycode')

        data = {
            'description': 'Some Description',
            # 'activation_delay': 3600,
            'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'emergency_data': 'a123',
            'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_emergency_authkey(self):
        """
        Tests to create an emergency code without emergency_authkey
        """

        url = reverse('emergencycode')

        data = {
            'description': 'Some Description',
            'activation_delay': 3600,
            # 'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'emergency_data': 'a123',
            'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_emergency_data(self):
        """
        Tests to create an emergency code without emergency_data
        """

        url = reverse('emergencycode')

        data = {
            'description': 'Some Description',
            'activation_delay': 3600,
            'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            # 'emergency_data': 'a123',
            'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_emergency_data_nonce(self):
        """
        Tests to create an emergency code without emergency_data_nonce
        """

        url = reverse('emergencycode')

        data = {
            'description': 'Some Description',
            'activation_delay': 3600,
            'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'emergency_data': 'a123',
            # 'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_emergency_sauce(self):
        """
        Tests to create an emergency code without emergency_sauce
        """

        url = reverse('emergencycode')

        data = {
            'description': 'Some Description',
            'activation_delay': 3600,
            'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'emergency_data': 'a123',
            'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            # 'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_emergency_data_no_hex(self):
        """
        Tests to create an emergency code with a emergency_data that is not hex encoded
        """

        url = reverse('emergencycode')

        data = {
            'description': 'Some Description',
            'activation_delay': -1,
            'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'emergency_data': 'a123X',
            'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_emergency_data_nonce_no_hex(self):
        """
        Tests to create an emergency code with a emergency_data_nonce that is not hex encoded
        """

        url = reverse('emergencycode')

        data = {
            'description': 'Some Description',
            'activation_delay': -1,
            'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'emergency_data': 'a123',
            'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA88X',
            'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_negative_activation_delay(self):
        """
        Tests to create an emergency code with a negative activation delay
        """

        url = reverse('emergencycode')

        data = {
            'description': 'Some Description',
            'activation_delay': -1,
            'emergency_authkey': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'emergency_data': 'a123',
            'emergency_data_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'emergency_sauce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)




class DeleteEmergencyCodeTest(APITestCaseExtended):
    """
    Test to delete an emergency code (DELETE)
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

        self.test_emergency_code_obj = models.Emergency_Code.objects.create(
            user = self.test_user_obj,
            description = 'Some description',
            activation_delay = 3600,
            emergency_authkey = make_password('abcd'),
            emergency_data=b'a123',
            emergency_data_nonce = 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            emergency_sauce = 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
        )


    def test_delete_success(self):
        """
        Tests to delete an emergency code
        """

        url = reverse('emergencycode')

        data = {
            'emergency_code_id': self.test_emergency_code_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_delete_failure_missing_emergency_code_id(self):
        """
        Tests to delete an emergency code
        """

        url = reverse('emergencycode')

        data = {
            # 'emergency_code_id': self.test_emergency_code_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_belongs_to_other_user(self):
        """
        Tests to delete an emergency code that belongs to another user
        """

        url = reverse('emergencycode')

        data = {
            'emergency_code_id': self.test_emergency_code_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_not_exist(self):
        """
        Tests to delete an emergency code that does not exist
        """

        url = reverse('emergencycode')

        data = {
            'emergency_code_id': '494d2d69-d4f9-4ab6-8f84-583928add37d',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class ReadEmergencyCodeTest(APITestCaseExtended):
    """
    Test to read an emergency code (GET)
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

        self.test_emergency_code_obj = models.Emergency_Code.objects.create(
            user = self.test_user_obj,
            description = 'Some description',
            activation_delay = 3600,
            emergency_authkey = make_password('abcd'),
            emergency_data =b'a123',
            emergency_data_nonce = 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            emergency_sauce = 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
        )


    def test_read_emergency_codes_success(self):
        """
        Tests to read all emergency_codes
        """

        url = reverse('emergencycode')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get('emegency_codes', False))
        self.assertEqual(len(response.data.get('emegency_codes')), 1)

        emergency_codes = response.data.get('emegency_codes')
        emergency_code = emergency_codes[0]

        self.assertEqual(emergency_code.get('id'), self.test_emergency_code_obj.id)
        self.assertEqual(emergency_code.get('description'), self.test_emergency_code_obj.description)
        self.assertEqual(emergency_code.get('activation_delay'), self.test_emergency_code_obj.activation_delay)


    def test_read_emergency_codes_success_without_permission(self):
        """
        Tests to read all emergency_codes with a user that has no permissions
        """

        url = reverse('emergencycode')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data.get('emegency_codes', True)) # Empty List
        self.assertEqual(len(response.data.get('emegency_codes')), 0)




class UpdateEmergencyCodeTest(APITestCaseExtended):
    """
    Test to update an emergency code (POST)
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


    def test_put_emergencycode(self):
        """
        Tests to update an emergency code
        """

        url = reverse('emergencycode')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

