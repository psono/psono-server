from django.core.urlresolvers import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status
from .base import APITestCaseExtended
from ..utils import readbuffer
from restapi import models

import random
import string
import os


class UserShareRightsWithInheritedRightTest(APITestCaseExtended):
    """
    Test to read/create/grant any share right, when normal inherited rights exist (nor not exist)
    """
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "b"
        self.test_email3 = "test3@example.com"
        self.test_email_bcrypt3 = "c"
        self.test_username = "test@psono.pw"
        self.test_username2 = "test2@psono.pw"
        self.test_username3 = "test3@psono.pw"
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
        self.test_secret_key_nonce3 = "f680cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
        self.test_private_key_nonce3 = "4398a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"

        self.test_user1_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='4c36bb1c6a33a5f3159afc2af6f6cda5391e85120ab5b7a7b18c0c9b7ef66c3d',
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
            user_sauce='7a3323247ce6de08b4631f2e5e87df1ed39a203610718101ece8a524f30211d4',
            is_email_active=True
        )

        self.test_user3_obj = models.User.objects.create(
            email=self.test_email3,
            email_bcrypt=self.test_email_bcrypt3,
            username=self.test_username3,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce3,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce3,
            user_sauce='2658403bcbbac0bb6dfe617b20a23d1fa9d2e8e074d06d6859481e4689fc6471',
            is_email_active=True
        )

        self.test_datastore1_obj = models.Data_Store.objects.create(
            user_id=self.test_user1_obj.id,
            type="my-type",
            description= "my-description",
            data= readbuffer("12345"),
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_datastore2_obj = models.Data_Store.objects.create(
            user_id=self.test_user2_obj.id,
            type="my-type",
            description= "my-description",
            data= readbuffer("12345"),
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_datastore3_obj = models.Data_Store.objects.create(
            user_id=self.test_user3_obj.id,
            type="my-type",
            description= "my-description",
            data= readbuffer("12345"),
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        # create share 1
        url = reverse('share')

        self.initial_data1 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '224c6e3d-667a-4f62-9300-e6f1773d1a2a',
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user1_obj)
        self.response1 = self.client.post(url, self.initial_data1)

        self.assertEqual(self.response1.status_code, status.HTTP_201_CREATED)

        # create share 2
        self.initial_data2 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': 'a6b609a0-5501-4c1f-a0ca-5c5a916ee68c',
            'parent_datastore_id': self.test_datastore2_obj.id,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        self.response2 = self.client.post(url, self.initial_data2)

        self.assertEqual(self.response2.status_code, status.HTTP_201_CREATED)

        # create share 3
        self.initial_data3 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': 'a4da7ed5-2963-4c8c-bcd7-6dcf879d7f9f',
            'parent_datastore_id': self.test_datastore3_obj.id,
        }

        self.client.force_authenticate(user=self.test_user3_obj)
        self.response3 = self.client.post(url, self.initial_data3)

        self.assertEqual(self.response3.status_code, status.HTTP_201_CREATED)

        #---------- shares in parent shares, for testing

        # create share 11
        url = reverse('share')

        self.initial_data11 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': 'd21d369a-7fa0-4d3a-bd9b-0781d494d987',
            'parent_share_id': self.response1.data['share_id'],
        }

        self.client.force_authenticate(user=self.test_user1_obj)
        self.response11 = self.client.post(url, self.initial_data11)

        self.assertEqual(self.response11.status_code, status.HTTP_201_CREATED)


    def test_first_level_inherited_rights(self):
        """
        Tests if the initial listing of share rights works with inherited rights of first level (user has rights on
        parent share)
        """

        # lets query for share11, expected failure because user2 has no rights on parent share1
        url = reverse('share', kwargs={'uuid': str(self.response11.data['share_id'])})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # setup: create rights for share1 for user2
        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.response1.data['share_id']),
            'title': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'title_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'type': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'type_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'read': True,
            'write': True,
            'grant': True,
            'user_id': str(self.test_user2_obj.id),
        }

        self.client.force_authenticate(user=self.test_user1_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # lets approve it
        models.User_Share_Right.objects.filter(pk=response.data['share_right_id']).update(accepted=True)

        # lets query for share11, expected success because user2 has rights on parent share1
        url = reverse('share', kwargs={'uuid': str(self.response11.data['share_id'])})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_second_level_inherited_rights(self):
        """
        Tests if the initial listing of share rights works with inherited rights of second level (user has rights on
        parent share of the parent share)
        """

        # create share 111 in share11
        url = reverse('share')

        initial_data111 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '32ef9ef2-488c-47f1-8ef0-5deb359840d9',
            'parent_share_id': self.response11.data['share_id'],
        }

        self.client.force_authenticate(user=self.test_user1_obj)
        response111 = self.client.post(url, initial_data111)

        self.assertEqual(response111.status_code, status.HTTP_201_CREATED)

        # lets query for share111, expected failure because user2 has no rights on parent share1
        url = reverse('share', kwargs={'uuid': str(response111.data['share_id'])})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # setup: create rights for share1 for user2
        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.response1.data['share_id']),
            'title': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'title_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'type': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'type_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'read': True,
            'write': True,
            'grant': True,
            'user_id': str(self.test_user2_obj.id),
        }

        self.client.force_authenticate(user=self.test_user1_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # lets approve it
        models.User_Share_Right.objects.filter(pk=response.data['share_right_id']).update(accepted=True)

        # lets query for share111, expected success because user2 has rights on parent of parent (share1)
        url = reverse('share', kwargs={'uuid': str(response111.data['share_id'])})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_overwrite_of_inherited_rights(self):
        """
        Tests if overwriting share rights work
        """

        # create share 111 in share11
        url = reverse('share')

        initial_data111 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '32ef9ef2-488c-47f1-8ef0-5deb359840d9',
            'parent_share_id': self.response11.data['share_id'],
        }

        self.client.force_authenticate(user=self.test_user1_obj)
        response111 = self.client.post(url, initial_data111)

        self.assertEqual(response111.status_code, status.HTTP_201_CREATED)

        # lets query for share111, expected failure because user2 has no rights on parent share1
        url = reverse('share', kwargs={'uuid': str(response111.data['share_id'])})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # setup: create rights for share1 for user2
        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.response1.data['share_id']),
            'title': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'title_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'type': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'type_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'read': True,
            'write': True,
            'grant': False,
            'user_id': str(self.test_user2_obj.id),
        }

        self.client.force_authenticate(user=self.test_user1_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # lets approve it
        models.User_Share_Right.objects.filter(pk=response.data['share_right_id']).update(accepted=True)

        # lets query for share111, expected success because user2 has rights on parent of parent (share1)
        url = reverse('share', kwargs={'uuid': str(response111.data['share_id'])})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # setup: create rights for share11 for user2, blocking read
        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.response11.data['share_id']),
            'title': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'title_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'type': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'type_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'read': False, # NO READ - share right that changes
            'write': True,
            'grant': False,
            'user_id': str(self.test_user2_obj.id),
        }

        self.client.force_authenticate(user=self.test_user1_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # lets query for share111, expected failure because user2 has his read rights revoked
        url = reverse('share', kwargs={'uuid': str(response111.data['share_id'])})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    # TODO Test everything with write
    # TODO Test everything with grant


