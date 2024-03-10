from django.urls import reverse
from django.conf import settings

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models

import random
import string
import binascii
import os

class CreateGroupTest(APITestCaseExtended):
    """
    Test to create a group (PUT)
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


    def test_create_success(self):
        """
        Tests to create a group
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


    def test_create_failure_no_name(self):
        """
        Tests to create a group without a name
        """

        url = reverse('group')

        data = {
            # 'name': 'Test Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_secret_key(self):
        """
        Tests to create a group without a secret key
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            # 'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_secret_key_nonce(self):
        """
        Tests to create a group without a secret key nonce
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123',
            # 'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_private_key(self):
        """
        Tests to create a group without a private key
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            # 'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_private_key_nonce(self):
        """
        Tests to create a group without a private key nonce
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            # 'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_public_key(self):
        """
        Tests to create a group without a public key
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            # 'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_secret_key(self):
        """
        Tests to create a group with a secret key that is no hex
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123X',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_secret_key_nonce(self):
        """
        Tests to create a group with a secret key nonce that is no hex
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0FX',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_private_key(self):
        """
        Tests to create a group with a private key that is no hex
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123X',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_private_key_nonce(self):
        """
        Tests to create a group with a private key nonce that is no hex
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA88X',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_public_key(self):
        """
        Tests to create a group with a public key nonce that is no hex
        """

        url = reverse('group')

        data = {
            'name': 'Test Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123X',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_name_too_short(self):
        """
        Tests to create a group with just two chars as name (min is 3)
        """

        url = reverse('group')

        data = {
            'name': 'Te',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_invalid_char_in_group(self):
        """
        Tests to create a group with an @ in the group name
        """

        url = reverse('group')

        data = {
            'name': 'Test@Group',
            'secret_key': 'a123',
            'secret_key_nonce': 'B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5',
            'private_key': 'a123',
            'private_key_nonce': 'D5BD6D7FCC2E086CFC28B2B2648ECA591D9F8201608A2D173E167D5B27ECA884',
            'public_key': 'a123',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class DeleteGroupTest(APITestCaseExtended):
    """
    Test to delete a group (DELETE)
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

        self.test_group_obj = models.Group.objects.create(
            name = 'Test Group',
            public_key = 'a123',
        )

        self.test_membership_obj = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj,
            creator = self.test_user_obj,
            secret_key = 'secret-key',
            secret_key_nonce = 'secret-key-nonce',
            secret_key_type = 'symmetric',
            private_key = 'private-key',
            private_key_nonce = 'private-key-nonce',
            private_key_type = 'symmetric',
            group_admin = True,
            accepted = True,
        )

        self.test_group_obj2 = models.Group.objects.create(
            name = 'Test Group',
            public_key = 'a123',
        )

        self.test_membership_obj2 = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj2,
            creator = self.test_user_obj,
            secret_key = 'secret-key',
            secret_key_nonce = 'secret-key-nonce',
            secret_key_type = 'symmetric',
            private_key = 'private-key',
            private_key_nonce = 'private-key-nonce',
            private_key_type = 'symmetric',
            group_admin = False,
            accepted = True,
        )

        self.test_group_obj3 = models.Group.objects.create(
            name = 'Test Group',
            public_key = 'a123',
        )

        self.test_membership_obj3 = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj3,
            creator = self.test_user_obj,
            secret_key = 'secret-key',
            secret_key_nonce = 'secret-key-nonce',
            secret_key_type = 'symmetric',
            private_key = 'private-key',
            private_key_nonce = 'private-key-nonce',
            private_key_type = 'symmetric',
            group_admin = True,
            accepted = False,
        )


    def test_delete_success(self):
        """
        Tests to delete a group
        """

        url = reverse('group')

        data = {
            'group_id': self.test_group_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_delete_failure_missing_group_id(self):
        """
        Tests to delete a group
        """

        url = reverse('group')

        data = {
            # 'group_id': self.test_group_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_no_group_admin(self):
        """
        Tests to delete a group without group admin rights
        """

        url = reverse('group')

        data = {
            'group_id': self.test_group_obj2.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_not_accepted(self):
        """
        Tests to delete a group without accepting the membership
        """

        url = reverse('group')

        data = {
            'group_id': self.test_group_obj3.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class ReadGroupTest(APITestCaseExtended):
    """
    Test to read a group (GET)
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
            authkey="abc",
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

        self.test_group_obj = models.Group.objects.create(
            name = 'Test Group 1',
            public_key = 'a123',
        )

        self.test_membership_obj = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj,
            creator = self.test_user_obj,
            secret_key = 'secret_key',
            secret_key_nonce = 'secret_key_nonce',
            secret_key_type = 'symmetric',
            private_key = 'private_key',
            private_key_nonce = 'private_key_nonce',
            private_key_type = 'symmetric',
            group_admin = True,
            accepted = True,
        )

        self.test_group_obj2 = models.Group.objects.create(
            name = 'Test Group 2',
            public_key = 'a123',
        )

        self.test_membership_obj2 = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj2,
            creator = self.test_user_obj,
            secret_key = 'secret_key',
            secret_key_nonce = 'secret_key_nonce',
            secret_key_type = 'symmetric',
            private_key = 'private_key',
            private_key_nonce = 'private_key_nonce',
            private_key_type = 'symmetric',
            group_admin = False,
            accepted = True,
        )

        self.test_group_obj3 = models.Group.objects.create(
            name = 'Test Group 3',
            public_key = 'a123',
        )

        self.test_membership_obj3 = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj3,
            creator = self.test_user_obj,
            secret_key = 'secret_key',
            secret_key_nonce = 'secret_key_nonce',
            secret_key_type = 'symmetric',
            private_key = 'private_key',
            private_key_nonce = 'private_key_nonce',
            private_key_type = 'symmetric',
            group_admin = True,
            accepted = False,
        )

        self.test_group_obj4 = models.Group.objects.create(
            name = 'Test Group 4',
            public_key = 'a123',
        )

        self.test_group_obj5 = models.Group.objects.create(
            name = 'Test Group 5',
            public_key = 'a123',
        )

        self.test_membership_obj5 = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj5,
            creator = self.test_user_obj,
            secret_key = 'secret_key',
            secret_key_nonce = 'secret_key_nonce',
            secret_key_type = 'symmetric',
            private_key = 'private_key',
            private_key_nonce = 'private_key_nonce',
            private_key_type = 'symmetric',
            group_admin = False,
            accepted = None,
        )


    def test_read_groups_success(self):
        """
        Tests to read all groups
        """

        url = reverse('group')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get('groups', False))
        self.assertEqual(len(response.data.get('groups')), 3)

        groups = response.data.get('groups')

        test_group_1_found = False
        test_group_2_found = False
        test_group_5_found = False
        found_something_else = False

        for group in groups:
            if group['name'] == 'Test Group 1':
                test_group_1_found = True
            elif group['name'] == 'Test Group 2':
                test_group_2_found = True
            elif group['name'] == 'Test Group 5':
                test_group_5_found = True
            else:
                found_something_else = True

        self.assertTrue(test_group_1_found)
        self.assertTrue(test_group_2_found)
        self.assertTrue(test_group_5_found)
        self.assertFalse(found_something_else)


    def test_read_groups_success_without_memberships(self):
        """
        Tests to read all groups
        """

        url = reverse('group')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data.get('groups', True)) # Empty List
        self.assertEqual(len(response.data.get('groups')), 0)



    def test_read_group_success(self):
        """
        Tests to read a specific group successful
        """

        url = reverse('group', kwargs={'group_id': self.test_group_obj.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get('members', False))
        self.assertEqual(response.data.get('name', False), 'Test Group 1')
        self.assertEqual(response.data.get('secret_key', False), 'secret_key')
        self.assertEqual(response.data.get('secret_key_nonce', False), 'secret_key_nonce')
        self.assertEqual(response.data.get('private_key', False), 'private_key')
        self.assertEqual(response.data.get('private_key_nonce', False), 'private_key_nonce')
        self.assertEqual(response.data.get('private_key_type', False), 'symmetric')
        self.assertNotEqual(response.data.get('group_share_rights', False), False)
        self.assertEqual(len(response.data.get('members')), 1)


    def test_read_group_success_no_group_admin(self):
        """
        Tests to read a specific group successful where no group admin rights exist
        """

        url = reverse('group', kwargs={'group_id': self.test_group_obj2.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get('members', False))
        self.assertEqual(response.data.get('name', False), 'Test Group 2')
        self.assertEqual(response.data.get('secret_key', False), 'secret_key')
        self.assertEqual(response.data.get('secret_key_nonce', False), 'secret_key_nonce')
        self.assertEqual(response.data.get('private_key', False), 'private_key')
        self.assertEqual(response.data.get('private_key_nonce', False), 'private_key_nonce')
        self.assertEqual(response.data.get('private_key_type', False), 'symmetric')
        self.assertNotEqual(response.data.get('group_share_rights', False), False)
        self.assertEqual(len(response.data.get('members')), 1)


    def test_read_group_success_declined(self):
        """
        Tests to read a specific group successful where the membership has been declined
        """

        url = reverse('group', kwargs={'group_id': self.test_group_obj3.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data.get('members', False))
        self.assertEqual(response.data.get('name', False), 'Test Group 3')
        self.assertEqual(response.data.get('secret_key', False), False)
        self.assertEqual(response.data.get('secret_key_nonce', False),False)
        self.assertEqual(response.data.get('private_key', False), False)
        self.assertEqual(response.data.get('private_key_nonce', False), False)
        self.assertEqual(response.data.get('private_key_type', False), False)
        self.assertEqual(response.data.get('group_share_rights', False), False)
        self.assertEqual(response.data.get('members', False), False)


    def test_read_group_success_not_accepted(self):
        """
        Tests to read a specific group successful where the membership hasn't been accepted yet
        """

        url = reverse('group', kwargs={'group_id': self.test_group_obj5.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data.get('members', False))
        self.assertEqual(response.data.get('name', False), 'Test Group 5')
        self.assertEqual(response.data.get('secret_key', False), False)
        self.assertEqual(response.data.get('secret_key_nonce', False),False)
        self.assertEqual(response.data.get('private_key', False), False)
        self.assertEqual(response.data.get('private_key_nonce', False), False)
        self.assertEqual(response.data.get('private_key_type', False), False)
        self.assertEqual(response.data.get('group_share_rights', False), False)
        self.assertEqual(response.data.get('members', False), False)
        self.assertNotEqual(response.data.get('user_id', False), False)
        self.assertNotEqual(response.data.get('user_username', False), False)


    def test_read_group_failure_no_membership(self):
        """
        Tests to read a specific group without any membership rights
        """

        url = reverse('group', kwargs={'group_id': self.test_group_obj4.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_read_group_failure_group_does_not_exist(self):
        """
        Tests to read a specific group that does not exist
        """

        url = reverse('group', kwargs={'group_id': 'cff06f13-a71a-43b5-8a0e-66816f35c565'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class UpdateGroupTest(APITestCaseExtended):
    """
    Test to update a group (POST)
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

        self.test_group_obj = models.Group.objects.create(
            name = 'Test Group 1',
            public_key = 'a123',
        )

        self.test_membership_obj = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj,
            creator = self.test_user_obj,
            secret_key = 'secret_key',
            secret_key_nonce = 'secret_key_nonce',
            secret_key_type = 'symmetric',
            private_key = 'private_key',
            private_key_nonce = 'private_key_nonce',
            private_key_type = 'symmetric',
            group_admin = True,
            accepted = True,
        )

        self.test_group_obj2 = models.Group.objects.create(
            name = 'Test Group 2',
            public_key = 'a123',
        )

        self.test_membership_obj2 = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj2,
            creator = self.test_user_obj,
            secret_key = 'secret_key',
            secret_key_nonce = 'secret_key_nonce',
            secret_key_type = 'symmetric',
            private_key = 'private_key',
            private_key_nonce = 'private_key_nonce',
            private_key_type = 'symmetric',
            group_admin = False,
            accepted = True,
        )

        self.test_group_obj3 = models.Group.objects.create(
            name = 'Test Group 3',
            public_key = 'a123',
        )

        self.test_membership_obj3 = models.User_Group_Membership.objects.create(
            user = self.test_user_obj,
            group = self.test_group_obj3,
            creator = self.test_user_obj,
            secret_key = 'secret_key',
            secret_key_nonce = 'secret_key_nonce',
            secret_key_type = 'symmetric',
            private_key = 'private_key',
            private_key_nonce = 'private_key_nonce',
            private_key_type = 'symmetric',
            group_admin = True,
            accepted = False,
        )

        self.test_group_obj4 = models.Group.objects.create(
            name = 'Test Group 4',
            public_key = 'a123',
        )


    def test_update_groups_success(self):
        """
        Tests to update a group
        """

        url = reverse('group')

        data = {
            'group_id': self.test_group_obj.id,
            'name': 'New Name',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        group = models.Group.objects.get(pk=self.test_group_obj.id)

        self.assertEqual(group.name, 'New Name')


    def test_update_groups_failure_no_group_admin(self):
        """
        Tests to update a group with no group admin rights
        """

        url = reverse('group')

        data = {
            'group_id': self.test_group_obj2.id,
            'name': 'New Name',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        group = models.Group.objects.get(pk=self.test_group_obj2.id)

        self.assertNotEqual(group.name, 'New Name')


    def test_update_groups_failure_not_accepted(self):
        """
        Tests to update a group where the membership has not been accepted
        """

        url = reverse('group')

        data = {
            'group_id': self.test_group_obj3.id,
            'name': 'New Name',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        group = models.Group.objects.get(pk=self.test_group_obj3.id)

        self.assertNotEqual(group.name, 'New Name')


    def test_update_groups_failure_no_membership(self):
        """
        Tests to update a group without any membership
        """

        url = reverse('group')

        data = {
            'group_id': self.test_group_obj4.id,
            'name': 'New Name',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        group = models.Group.objects.get(pk=self.test_group_obj4.id)

        self.assertNotEqual(group.name, 'New Name')


    def test_update_groups_failure_group_does_not_exist(self):
        """
        Tests to update a group where the group does not exist
        """

        url = reverse('group')

        data = {
            'group_id': 'a6f82e75-2929-4ebc-9a65-231b92aa99f0',
            'name': 'New Name',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
