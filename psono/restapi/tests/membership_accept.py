from django.urls import reverse
from django.conf import settings

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models

import json
import random
import string
import binascii
import os


class AcceptMembershipTest(APITestCaseExtended):
    """
    Test to accept a membership (POST)
    """
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
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
            username=self.test_username,
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

        self.test_membership_obj4 = models.User_Group_Membership.objects.create(
            user = self.test_user_obj2,
            group = self.test_group_obj4,
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

    def test_read_accept_membership(self):
        """
        Tests GET method on membership_accept
        """

        url = reverse('membership_accept')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_accept_failure_already_accepted_share(self):
        """
        Tests to accept a membership that has already been accepted
        """

        url = reverse('membership_accept')

        data = {
            'membership_id': self.test_membership_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_failure_with_no_membership_id(self):
        """
        Tests to accept a membership without a membership id
        """

        url = reverse('membership_accept')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_failure_with_already_declined_membership(self):
        """
        Tests to accept a membership with an already declined membership
        """

        url = reverse('membership_accept')

        data = {
            'membership_id': str(self.test_membership_obj3.id),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_failure_of_membership_that_belongs_to_other_user(self):
        """
        Tests to accept a membership that belongs to another user
        """

        url = reverse('membership_accept')

        data = {
            'membership_id': str(self.test_membership_obj4.id),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_success(self):
        """
        Tests to accept a membership with a not yet accepted membership
        """

        url = reverse('membership_accept')

        data = {
            'membership_id': str(self.test_membership_obj5.id),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_accept_membership(self):
        """
        Tests PUT method on membership_accept
        """

        url = reverse('membership_accept')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_accept_membership(self):
        """
        Tests DELETE method on membership_accept
        """

        url = reverse('membership_accept')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)