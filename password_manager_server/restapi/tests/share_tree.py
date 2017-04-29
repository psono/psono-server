from django.core.urlresolvers import reverse
from django.core import mail
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from datetime import timedelta
from django.db import IntegrityError

from rest_framework import status
from rest_framework.test import APITestCase, APIClient

from restapi import models
from restapi.utils import generate_activation_code

from base import APITestCaseExtended

import random
import string
import os

from uuid import UUID, uuid4

class ShareTests(APITestCaseExtended):
    def setUp(self):

        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "b"
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
            user_sauce='af8d7c6e835a4e378655e8e11fa0b09afc2f08acf0be1d71d9fa048a2b09d2eb',
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
            user_sauce='f2b5314ccdd726c3f4deabf5efccb0de5183796a9ecc691565aff2edf8c60249',
            is_email_active=True
        )

        self.test_datastore1_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= "12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_datastore2_obj = models.Data_Store.objects.create(
            user_id=self.test_user2_obj.id,
            type="my-type",
            description= "my-description",
            data= "12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

    def test_share_tree_on_insert(self):
        """
        Tests to insert the share and check the share_tree
        """

        # lets try to create a share
        url = reverse('share')

        initial_data1 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '2711c138-21a3-4c46-8bec-ba70442fefe3',
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data1)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_id', False), False,
                            'Share id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'Share id is no valid UUID')

        new_share_id = str(response.data.get('share_id'))

        share_trees = models.Share_Tree.objects.all()

        self.assertEqual(share_trees.count(), 1,
                         'Exactly 1 share tree object should be created, but we got: ' + str(share_trees.count()))

        # lets see if it also works for shares with a parent

        initial_data2 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': 'dbf9f536-4c5d-48ed-a55f-8ce6ad4b28db',
            'parent_share_id': new_share_id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data2)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_id', False), False,
                            'Share id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'Share id is no valid UUID')
        new_child_share_id = str(response.data.get('share_id'))

        share_trees = models.Share_Tree.objects.all()

        self.assertEqual(share_trees.count(), 2,
                         'Exactly 2 share tree objects should be created, but we got: ' + str(share_trees.count()))

        never_checked = True
        for t in share_trees:
            if str(t.parent_share_id) != new_share_id:
                continue
            never_checked = False
            expected_path = initial_data1['link_id'].replace("-", "")+\
                            '.'+initial_data2['link_id'].replace("-", "")
            self.assertEqual(t.path, expected_path,
                             'Path should only be "' + expected_path +' but we got ' + t.path)
            self.assertEqual(str(t.share_id), new_child_share_id, 'Share should be the last created share')

        self.assertEqual(never_checked, False, 'Checks were bypassed')

        # lets see if it also works for shares with a parent who have parents

        initial_data3 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '7cf062ee-2719-4bf6-847e-9e1f2cbee03e',
            'parent_share_id': new_child_share_id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data3)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_id', False), False,
                            'Share id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'Share id is no valid UUID')
        newer_child_share_id = str(response.data.get('share_id'))

        share_trees = models.Share_Tree.objects.all()

        self.assertEqual(share_trees.count(), 3,
                         'Exactly 3 share tree objects should be created, but we got: ' + str(share_trees.count()))

        never_checked = True
        for t in share_trees:
            if str(t.parent_share_id) != new_child_share_id:
                continue
            never_checked = False
            expected_path = initial_data1['link_id'].replace("-", "")+\
                            '.'+initial_data2['link_id'].replace("-", "")+\
                            '.'+initial_data3['link_id'].replace("-", "")
            self.assertEqual(t.path, expected_path,
                             'Path should only be "' + expected_path +'" but we got ' + t.path)
            self.assertEqual(str(t.share_id), newer_child_share_id, 'Share should be the last created share')
        self.assertEqual(never_checked, False, 'Checks were bypassed')

    def test_share_tree_on_insert_duplicate_link_id(self):
        """
        Tests to insert the share with duplicate link id and check the share_tree
        """

        # lets try to create a share
        url = reverse('share')

        initial_data1 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '2711c138-21a3-4c46-8bec-ba70442fefe3',
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data1)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        share_trees = models.Share_Tree.objects.all()

        self.assertEqual(share_trees.count(), 1,
                         'Exactly 1 share tree object should be created, but we got: ' + str(share_trees.count()))

        # lets see if it also works for shares with a parent

        initial_data2 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': initial_data1['link_id'],
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data2)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        share_trees = models.Share_Tree.objects.all()

        self.assertEqual(share_trees.count(), 1,
                         'Exactly 1 share tree object should be created, but we got: ' + str(share_trees.count()))


class ShareTreeModificationTests(APITestCaseExtended):
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
        self.test_secret_key_nonce3 = "f580cc990ace7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
        self.test_private_key_nonce3 = "4298a9ab3d9d5d8643dfd4445adc30301b56aab650497fb8"

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
            user_sauce='ada037674acdbc7d82446c0f8b8a39ebaaee596f42d205012796dc07bbd7c45a',
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
            user_sauce='081c20d33eb13a953e35ef785daefd945bd0af0a568be0dab01b235d4e610234',
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
            user_sauce='64657a91c8c38b0a05cbd12f8ac9531aa7f2846cae15a1537d4f5579290f1454',
            is_email_active=True
        )

        self.test_datastore1_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description="my-description",
            data="12345",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_datastore2_obj = models.Data_Store.objects.create(
            user_id=self.test_user2_obj.id,
            type="my-type",
            description="my-description",
            data="12345",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        url = reverse('share')

        # lets try to create a share chain of 4 shares
        # DS1 -> 1 -> 2 -> 3 -> 4

        self.initial_data1 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response1 = self.client.post(url, self.initial_data1)

        self.initial_data2 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_share_id': self.response1.data.get('share_id')
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response2 = self.client.post(url, self.initial_data2)

        self.initial_data3 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_share_id': self.response2.data.get('share_id')
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response3 = self.client.post(url, self.initial_data3)

        self.initial_data4 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_share_id': self.response3.data.get('share_id')
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response4 = self.client.post(url, self.initial_data4)

        # lets try to create a share chain of 4 other shares
        # DS1 -> 5 -> 6 -> 7 -> 8

        self.initial_data5 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response5 = self.client.post(url, self.initial_data5)

        self.initial_data6 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_share_id': self.response5.data.get('share_id')
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response6 = self.client.post(url, self.initial_data6)

        self.initial_data7 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_share_id': self.response6.data.get('share_id')
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response7 = self.client.post(url, self.initial_data7)

        self.initial_data8 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_share_id': self.response7.data.get('share_id')
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response8 = self.client.post(url, self.initial_data8)

        # lets also give the other user a chain of 2 shares
        # DS2 -> B1 -> B2

        self.initial_dataB1 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_datastore_id': self.test_datastore2_obj.id,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        self.responseB1 = self.client.post(url, self.initial_dataB1)

        self.initial_dataB2 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_share_id': self.responseB1.data.get('share_id')
        }

        # lets also give the other user a chain of 1 shares
        # DS2 -> B3

        self.client.force_authenticate(user=self.test_user2_obj)
        self.responseB2 = self.client.post(url, self.initial_dataB2)

        self.initial_dataB3 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': uuid4(),
            'parent_datastore_id': self.test_datastore2_obj.id,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        self.responseB3 = self.client.post(url, self.initial_dataB3)


    def test_link_of_share_to_other_parent_share_with_badly_formatted_uuid(self):
        """
        Tests to link a share to other parent_share with badly formatted uuid
        """
        # lets try to create the a link to a share without rights to a parent_share
        url = reverse('share_link', kwargs={'uuid': '123456'})

        request_data = {
            'share_id': self.response7.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_link_of_share_to_other_datastore_without_rights_for_the_share(self):
        """
        Tests to link a share to other datastore without any rights for it
        """
        # lets try to create the a link to a share without rights to a datastore
        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_datastore_id': self.test_datastore2_obj.id,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get('resource_id', False), str(request_data['share_id']),
                            'Should be declined because of no rights for share')

    def test_link_of_share_to_other_datastore_without_rights_for_the_datastore(self):
        """
        Tests to link a share to other datastore without any rights for the datastore
        """

        # lets try to create the link to a share with a datastore without rights
        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_datastore_id': self.test_datastore2_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.assertEqual(response.data.get('resource_id', False), str(request_data['parent_datastore_id']),
                            'Should be declined because of no rights for datastore')


    def test_link_of_share_to_other_parent_share_without_rights_for_the_share(self):
        """
        Tests to link a share to other parent_share without any rights for the share
        """

        # lets try to create the a link to a share without rights to a parent_share
        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_share_id': self.responseB3.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get('resource_id', False), str(request_data['share_id']),
                         'Should be declined because of no rights for share')


    def test_link_of_share_to_other_parent_share_without_rights_for_the_parent_share(self):
        """
        Tests to link a share to other parent_share without any rights for the parent_share
        """

        # lets try to create the link to a share with a parent_share without rights
        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_share_id': self.responseB3.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.assertEqual(str(response.data.get('resource_id', '')), str(request_data['parent_share_id']),
                         'Should be declined because of no rights for parent_share')


    def test_link_of_share_to_other_not_existing_share(self):
        """
        Tests to link a share to other not existing share
        """

        # lets try to create the a link to a share without rights to a parent_share
        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': '9289cd38-380d-416e-88db-de2880fd9ba7',
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_link_of_share_to_other_not_existing_parent_share(self):
        """
        Tests to link a share to other not existing parent_share
        """

        # lets try to create the a link to a share without rights to a parent_share
        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_share_id': '9289cd38-380d-416e-88db-de2880fd9ba7',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_link_of_share_to_other_parent_share(self):
        """
        Tests to link a share to other parent_share
        """

        share_trees = models.Share_Tree.objects.all()
        expected_share_tree_count = 11

        self.assertEqual(share_trees.count(), expected_share_tree_count,
                         'Exactly ' + str(
                             expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))

        # lets try to create the a link to a share without rights to a parent_share
        link_id = uuid4()
        url = reverse('share_link', kwargs={'uuid': str(link_id)})

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        share_trees = models.Share_Tree.objects.all()
        expected_share_tree_count = 13

        self.assertEqual(share_trees.count(), expected_share_tree_count,
                         'Exactly ' + str(
                             expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))

        share_trees = models.Share_Tree.objects.filter(path__match='*.'+str(link_id).replace("-", "")+'.*')

        expected_share_tree_count = 2
        self.assertEqual(share_trees.count(), expected_share_tree_count,
                 'Exactly ' + str(
                     expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                     share_trees.count()))

        share_trees = models.Share_Tree.objects.filter(path__match='*.'+str(link_id).replace("-", "")+'.*', share_id = self.response7.data.get('share_id'))

        expected_share_tree_count = 1
        self.assertEqual(share_trees.count(), expected_share_tree_count,
                 'Exactly ' + str(
                     expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                     share_trees.count()))

        self.assertEqual(share_trees[0].parent_share_id, request_data['parent_share_id'],
                         'Parent share is incorrect')
        self.assertEqual(share_trees[0].parent_datastore_id, None,
                         'Datastore is incorrect')

        expected_path = str(self.initial_data5['link_id']).replace("-", "")+'.'+str(link_id).replace("-", "")
        self.assertEqual(share_trees[0].path, expected_path,
                         'Path is incorrect')

        share_trees = models.Share_Tree.objects.filter(path__match='*.'+str(link_id).replace("-", "")+'.*', parent_share_id = self.response7.data.get('share_id'))

        expected_share_tree_count = 1
        self.assertEqual(share_trees.count(), expected_share_tree_count,
                 'Exactly ' + str(
                     expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                     share_trees.count()))

        self.assertEqual(share_trees[0].share_id, self.response8.data.get('share_id'),
                         'Share is incorrect')
        self.assertEqual(share_trees[0].parent_datastore_id, None,
                         'Datastore is incorrect')

        expected_path = str(self.initial_data5['link_id']).replace("-", "")\
                        +'.'+str(link_id).replace("-", "")\
                        +'.'+str(self.initial_data8['link_id']).replace("-", "")
        self.assertEqual(share_trees[0].path, expected_path,
                         'Path is incorrect')


    def test_link_of_share_to_other_parent_share_with_duplicate_link_uuid(self):
        """
        Tests to link a share to other parent_share with duplicate link uuid
        """

        # lets try to create the a link to a share without rights to a parent_share
        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_link_of_share_in_datastore(self):
        """
        Tests to link a share to other parent_share
        """

        share_trees = models.Share_Tree.objects.all()
        expected_share_tree_count = 11

        self.assertEqual(share_trees.count(), expected_share_tree_count,
                         'Exactly ' + str(
                             expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))

        # lets try to create the a link to a share without rights to a parent_share
        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        share_trees = models.Share_Tree.objects.all()
        expected_share_tree_count = 13

        self.assertEqual(share_trees.count(), expected_share_tree_count,
                         'Exactly ' + str(
                             expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))

        share_trees = models.Share_Tree.objects.filter(path__match='*.'+str(link_id).replace("-", "")+'.*')

        expected_share_tree_count = 2
        self.assertEqual(share_trees.count(), expected_share_tree_count,
                 'Exactly ' + str(
                     expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                     share_trees.count()))

        share_trees = models.Share_Tree.objects.filter(path__match='*.'+str(link_id).replace("-", "")+'.*', share_id = self.response7.data.get('share_id'))

        expected_share_tree_count = 1
        self.assertEqual(share_trees.count(), expected_share_tree_count,
                 'Exactly ' + str(
                     expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                     share_trees.count()))

        self.assertEqual(share_trees[0].parent_share_id, None,
                         'Parent share is incorrect')
        self.assertEqual(share_trees[0].parent_datastore_id, request_data['parent_datastore_id'],
                         'Datastore is incorrect')

        expected_path = str(link_id).replace("-", "")
        self.assertEqual(share_trees[0].path, expected_path,
                         'Path is incorrect')

        share_trees = models.Share_Tree.objects.filter(path__match='*.'+str(link_id).replace("-", "")+'.*', parent_share_id = self.response7.data.get('share_id'))

        expected_share_tree_count = 1
        self.assertEqual(share_trees.count(), expected_share_tree_count,
                 'Exactly ' + str(
                     expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                     share_trees.count()))

        self.assertEqual(share_trees[0].share_id, self.response8.data.get('share_id'),
                         'Share is incorrect')
        self.assertEqual(share_trees[0].parent_datastore_id, None,
                         'Datastore is incorrect')

        expected_path = str(link_id).replace("-", "")\
                        +'.'+str(self.initial_data8['link_id']).replace("-", "")
        self.assertEqual(share_trees[0].path, expected_path,
                         'Path is incorrect')

    # TODO Test move share_tree obj (POST)


    # TODO Test delete share_tree obj (DELETE)

    def test_delete_with_badly_formatted_uuid(self):
        """
        Tests to delete a share_right with badly formed uuid
        """

        url = reverse('share_link', kwargs={'uuid': "12345"})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_share_that_does_not_exist(self):
        """
        Tests to delete a share_right
        """

        share_trees = models.Share_Tree.objects.all()
        expected_share_tree_count = 11

        self.assertEqual(share_trees.count(), expected_share_tree_count,
                         'Exactly ' + str(
                             expected_share_tree_count) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))

        # lets try to create the a link to a share without rights to a parent_share
        url = reverse('share_link')

        request_data = {
            'link_id': 'b48cbd50-1aba-4389-90ce-3bed32c831e3'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_delete_share_that_exists(self):
        """
        Tests to delete a share_right
        """

        share_trees = models.Share_Tree.objects.all()
        expected_share_tree_count_before = 11
        expected_share_tree_count_after = 13

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)



        self.assertEqual(share_trees.count(), expected_share_tree_count_after,
                         'Exactly ' + str(
                             expected_share_tree_count_after) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))


        # lets try to create the a link to a share without rights to a parent_share
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id)
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(share_trees.count(), expected_share_tree_count_before,
                         'Exactly ' + str(
                             expected_share_tree_count_before) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))


    def test_delete_share_with_no_write_rights_on_parent_share(self):
        """
        Tests to delete a share_right with no write rights on parent share
        """

        share_trees = models.Share_Tree.objects.all()
        expected_share_tree_count_after = 13

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)



        self.assertEqual(share_trees.count(), expected_share_tree_count_after,
                         'Exactly ' + str(
                             expected_share_tree_count_after) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))

        # remove grant right on share
        models.User_Share_Right.objects.filter(share_id=self.response5.data.get('share_id'), user=self.test_user_obj).update(write=False)


        # lets try to create the a link to a share without rights to a parent_share
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id)
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.assertEqual(share_trees.count(), expected_share_tree_count_after,
                         'Exactly ' + str(
                             expected_share_tree_count_after) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))


    def test_delete_share_with_no_write_rights_on_parent_datastore(self):
        """
        Tests to delete a share_right with no write rights on parent datastore
        """

        share_trees = models.Share_Tree.objects.all()
        expected_share_tree_count_after = 13

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response7.data.get('share_id'),
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)



        self.assertEqual(share_trees.count(), expected_share_tree_count_after,
                         'Exactly ' + str(
                             expected_share_tree_count_after) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))

        # change datastore owner
        models.Data_Store.objects.filter(pk=self.test_datastore1_obj.id).update(user=self.test_user3_obj)


        # lets try to create the a link to a share without rights to a parent_share
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id)
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.assertEqual(share_trees.count(), expected_share_tree_count_after,
                         'Exactly ' + str(
                             expected_share_tree_count_after) + ' share tree objects should be created, but we got: ' + str(
                             share_trees.count()))


    def test_move_not_existing_link(self):
        """
        Tests to move not existing link
        """

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response8.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': 'd7d63a3a-d2ce-4c52-a9bb-37baf13d814f',
            'new_parent_share_id': self.response6.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_move_share_to_new_parent_share(self):
        """
        Tests to move share to new parent share
        """

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response8.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'new_parent_share_id': self.response6.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_move_share_to_new_parent_share_with_no_write_rights_on_new_parent(self):
        """
        Tests to move share to new parent share with no write rights on new parent
        """

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response8.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # change share_rights to no write
        models.User_Share_Right.objects.filter(share_id=self.response6.data.get('share_id'), user=self.test_user_obj).update(write=False)

        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'new_parent_share_id': self.response6.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_move_share_to_new_parent_share_with_no_write_rights_on_old_parent(self):
        """
        Tests to move share to new parent share with no write rights on old parent
        """

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response8.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # change share_rights to no write
        models.User_Share_Right.objects.filter(share_id=self.response5.data.get('share_id'), user=self.test_user_obj).update(write=False)

        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'new_parent_share_id': self.response6.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_move_share_to_new_parent_share_while_no_grant_permissions_on_share(self):
        """
        Tests to move share to new parent share while the user has no grant permissions on share
        """

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response8.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # change share_rights to no write
        models.User_Share_Right.objects.filter(share_id=self.response8.data.get('share_id'), user=self.test_user_obj).update(grant=False)

        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'new_parent_share_id': self.response6.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_move_share_to_new_parent_share_which_does_not_exist(self):
        """
        Tests to move share to new parent share which does not exist
        """

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response8.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'new_parent_share_id': 'aefb1f49-d61f-411b-9d3d-8f6ef82a3014',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_move_share_to_new_datastore(self):
        """
        Tests to move share to new datastore
        """

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response8.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'new_parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_move_share_to_new_datastore_which_does_not_belong_to_the_user(self):
        """
        Tests to move share to new datastore which does not belong to the user
        """

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response8.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'new_parent_datastore_id': self.test_datastore2_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_move_share_to_new_datastore_which_does_not_exist(self):
        """
        Tests to move share to new datastore which does not exist
        """

        link_id = uuid4()
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'share_id': self.response8.data.get('share_id'),
            'parent_share_id': self.response5.data.get('share_id'),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str(link_id),
            'new_parent_datastore_id': '598da51a-3c96-4f75-beec-dc91f92905ec',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_move_from_not_own_datastore_to_own_datastore(self):
        """
        Tests to move share from another users datastore to own datastore
        """

        models.User_Share_Right.objects.filter(share_id=self.responseB3.data.get('share_id'), user=self.test_user2_obj).update(user=self.test_user_obj)

        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str(self.initial_dataB3['link_id']),
            'new_parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_move_of_share_to_other_parent_share_with_badly_formatted_uuid(self):
        """
        Tests to move a share to other datastore with badly formatted uuid
        """

        # lets try to move it
        url = reverse('share_link')

        request_data = {
            'link_id': str('123456'),
            'new_parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, request_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
