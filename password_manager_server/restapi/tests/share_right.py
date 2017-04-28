from django.core.urlresolvers import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status

from restapi import models

from base import APITestCaseExtended

import random
import string
import os

from uuid import UUID


class UserShareRightTest(APITestCaseExtended):
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
            user_sauce='082202ea53a9f64459b8217ebbdea19f6cb385d8d529327053f54a9b9861dcf1',
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='2a6792ec2ae557f1ba8b5ec5e64a495bde07fa1a69104ce1fb80b1e779fcb8dd',
            is_email_active=True
        )

    def test_list_share_right_without_credentials(self):
        """
        Tests if someone gets share rights without credentials
        """

        url = reverse('share_right')

        data = {}

        response = self.client.get(url, data, user=self.test_user_obj)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIsInstance(response.data.get('share_rights', False), list,
                                 'We got some data even with a 401')

    def test_list_share_right(self):
        """
        Tests if the initial listing of share rights works
        """

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 0,
                         'Shares hold already data, but should not contain any data at the beginning')

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
        )

        # and now insert our dummy share_right
        self.test_share_right1_ob = models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            title=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            title_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type= ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            type_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            read=True,
            write=True,
            grant=True,
            user_id=str(self.test_user2_obj.id),
            accepted=True
        )

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 1,
                         'Shares should contain 1 entry')

    def test_read_share_with_no_defined_rights(self):
        """
        Tests read share with no defined rights
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        # Then lets try to get it with the wrong user which has not even defined rights for this share

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 0,
                         'No share should exist for this user')

        # let try to query it directly with wrong user

        url = reverse('share_right', kwargs={'uuid': str(self.test_share1_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(response.data.get('shares', False),
                         'Shares do not exist in list shares response')

    def test_read_share_with_read_rights(self):
        """
        Tests read share with read rights
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        # now lets define rights for this user
        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        # Then lets try to get it with the user which has defined rights for this share including read

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')

        self.assertEqual(len(response.data.get('share_rights', False)), 1,
                         'Exactly 1 share right should exist for this user')

        self.assertEqual(response.data.get('share_rights', False)[0]['read'], True,
                         'Read should be true')

        # let try to query it directly with user which has defined rights for this share including read

        url = reverse('share_right', kwargs={'uuid': str(self.test_share_right1_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data.get('shares', False),
                         'Shares do not exist in list shares response')

        # let try to query the share directly with user which has defined rights for this share including read

        url = reverse('share', kwargs={'uuid': str(self.test_share1_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data.get('data', ''), self.test_share1_obj.data,
                         'Share should contain data and data should be equal to the original data')
        self.assertEqual(response.data.get('data_nonce', ''), self.test_share1_obj.data_nonce,
                         'Share should contain the data nonce and data should be equal to the original data nonce')

    def test_read_share_with_no_read_rights(self):
        """
        Tests read share with no read rights
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        # now lets define rights for this user
        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=False,
            grant=True,
            accepted=True
        )

        # Then lets try to get it with the user which has defined rights for this share but no read

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')

        self.assertEqual(len(response.data.get('share_rights', False)), 1,
                         'Exactly 1 share right should exist for this user')

        self.assertEqual(response.data.get('share_rights', False)[0]['read'], False,
                         'Read should be false')

        # let try to query it directly with user which has defined rights for this share but no read

        url = reverse('share_right', kwargs={'uuid': str(self.test_share_right1_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data.get('shares', False),
                         'Shares do not exist in list shares response')

        # let try to query the share directly with user which has defined rights for this share but no read

        url = reverse('share', kwargs={'uuid': str(self.test_share1_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_grant_share_right_with_no_rights(self):
        """
        Tests grant share right without rights
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        # lets try to create a share right for this share

        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.test_share1_obj.id),
            'title': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'title_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'type': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'type_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'read': True,
            'write': True,
            'grant': True,
            'user_id': str(self.test_user2_obj.id),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_grant_share_right_with_right(self):
        """
        Tests to insert the share right and check the rights to access it
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )
        models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
        )

        # lets try to create a share right for this share

        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.test_share1_obj.id),
            'title': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'title_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'type': ''.join(random.choice(string.ascii_lowercase) for _ in range(512)),
            'type_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'read': True,
            'write': True,
            'grant': True,
            'user_id': str(self.test_user2_obj.id),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_right_id', False), False,
                            'Share id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_right_id', '')),
                                'Share id is no valid UUID')

        new_share_right_id = str(response.data.get('share_right_id'))

        # lets try to get the share back in the list now with rights

        url = reverse('share')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                              'Shares do not exist in list shares response')
        self.assertEquals(len(response.data.get('shares', False)), 1,
                          'The should only be one share')

        # Then lets try to get it in the overview

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 1,
                         'One share should exist for this user')

        target_store = {
            'id': UUID(new_share_right_id, version=4),
            'share_id': self.test_share1_obj.id,
            'title': initial_data['title'],
            'title_nonce': initial_data['title_nonce'],
            'type': initial_data['type'],
            'type_nonce': initial_data['type_nonce'],
            'read': True,
            'write': True,
            'grant': True,
            'key': initial_data['key'],
            'key_nonce': initial_data['key_nonce'],
        }

        self.assertEqual(response.data.get('share_rights', False)[0], target_store)

    def test_delete_share_right_with_no_grant_right(self):
        """
        Tests to delete the share right with no grant right
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )
        models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=False,
            accepted=True
        )
        test_user_share_rights = models.User_Share_Right.objects.create(
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            share_id=self.test_share1_obj.id,
            read=False,
            write=False,
            grant=False,
            accepted=True
        )

        self.assertEqual(models.User_Share_Right.objects.filter(pk=test_user_share_rights.id).count(), 1,
                         'Exactly one share right with this id should exist')

        url = reverse('share_right')

        data = {
            'share_right_id': str(test_user_share_rights.id)
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_share_right_without_uuid(self):
        """
        Tests to delete something without uuid
        """

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_share_right_with_grant_rights(self):
        """
        Tests to delete the share right with grant rights
        """

        # Lets first insert our dummy share
        test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )
        models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=test_share1_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
        )

        test_user_share_rights = models.User_Share_Right.objects.create(
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            share_id=test_share1_obj.id,
            read=False,
            write=False,
            grant=False,
            accepted=True
        )

        self.assertEqual(models.User_Share_Right.objects.filter(pk=test_user_share_rights.id).count(), 1,
                         'Exactly one share right with this id should exist')

        url = reverse('share_right')

        data = {
            'share_right_id': str(test_user_share_rights.id)
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.User_Share_Right.objects.filter(pk=test_user_share_rights.id).count(), 0,
                         'Share right with this id should have been deleted')
