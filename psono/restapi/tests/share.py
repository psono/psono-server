from django.urls import reverse

from rest_framework import status

from restapi import models

from .base import APITestCaseExtended

import random
import string

from uuid import UUID



class EmptyShareTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "b"
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='e1acaa936aba823ec09933f8213e39b9e4d58d3ccfbf6aca57cd7eb039549677',
            is_email_active=True
        )


    def test_list_empty_shares(self):
        """
        Tests if the initial listing of no shares works
        """

        url = reverse('share')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('shares', False)), 0,
                         'Only 1 share should exist at the beginning.')

    def test_get_with_bad_formatted_share_id(self):
        """
        Tests if bad formatted share ids make a problem
        """

        url = reverse('share', kwargs={'share_id': '3c2c0f4d'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_get_not_existing_share(self):
        """
        Tests to get a share that does not exist
        """

        url = reverse('share', kwargs={'share_id': '3c2c0f4d-8fae-4790-b5ad-55a4ae78024a'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class ReadShareTests(APITestCaseExtended):
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
            username=self.test_username,
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='101e54acafea8a138916e33fcc631364eba744c7f7f76ecd1741e421e2d54de5',
            is_email_active=True
        )

        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='f08ec82fa3ddd3f0948bcd2b7aa00ecca13412ab1263cfe76ab92a0bfb87d9c1',
            is_email_active=True
        )

    def test_list_shares(self):
        """
        Tests if the initial listing of shares works
        """

        url = reverse('share')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('shares', False)), 1,
                         'Only 1 share should exist at the beginning.')

    def test_list_empty_shares(self):
        """
        Tests if the listing of no shares work
        """

        url = reverse('share')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('shares', False)), 0,
                         'Only 1 share should exist at the beginning.')

    def test_list_shares_without_credentials(self):
        """
        Tests if someone gets shares without credentials
        """

        url = reverse('share')

        data = {}

        response = self.client.get(url, data, user=self.test_user_obj)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIsInstance(response.data.get('shares', False), list,
                                 'We got some data even with a 401')

class CreateShareTests(APITestCaseExtended):
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
            username=self.test_username,
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='101e54acafea8a138916e33fcc631364eba744c7f7f76ecd1741e421e2d54de5',
            is_email_active=True
        )


        self.test_datastore1_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= b"12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
            data_nonce="12345"
        )

        self.test_user_share_right1_obj = models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='f08ec82fa3ddd3f0948bcd2b7aa00ecca13412ab1263cfe76ab92a0bfb87d9c1',
            is_email_active=True
        )

        self.test_share2_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data=b"my-data",
            data_nonce="12345"
        )


        self.test_datastore2_obj = models.Data_Store.objects.create(
            user_id=self.test_user2_obj.id,
            type="my-type",
            description= "my-description",
            data= b"12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_user_share_right2_obj = models.User_Share_Right.objects.create(
            creator_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            share_id=self.test_share2_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
        )

    def test_insert_share(self):
        """
        Tests to insert the share and check the rights to access it
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '47986868-5950-476f-b532-3ed3a80d515d',
            'parent_share_id': self.test_share1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_id', False), False,
                            'Share id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'Share id is no valid UUID')

        new_share_id = str(response.data.get('share_id'))

        # lets try to get it back in the list

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                              'Shares do not exist in list shares response')
        self.assertGreater(len(response.data.get('shares', False)), 0,
                           'Shares should now hold some data')

        found = False

        for store in response.data.get('shares', []):
            if str(store.get('id', '')) == new_share_id:
                self.assertFalse(found,
                                 'Found our share twice in the returned list')
                found = True

                target_store = {
                    'share_right_user_id': self.test_user_obj.id,
                    'id': UUID(new_share_id, version=4),
                    # 'data': str(initial_data['data']),
                    # 'data_nonce': unicode(initial_data['data_nonce']),
                    'share_right_id': store['share_right_id'],
                    'share_right_create_date': store['share_right_create_date'],
                    'share_right_write_date': store['share_right_write_date'],
                    'share_right_create_user_id': self.test_user_obj.id,
                    'share_right_create_user_username': self.test_user_obj.username,
                    'share_right_create_user_public_key': self.test_user_obj.public_key,
                    'share_right_title': "",
                    'share_right_title_nonce': "",
                    'share_right_type': None,
                    'share_right_type_nonce': None,
                    'share_right_key': initial_data['key'],
                    'share_right_key_nonce': initial_data['key_nonce'],
                    'share_right_key_type': initial_data['key_type'],
                    'share_right_read': True,
                    'share_right_write': True,
                    'share_right_grant': True,
                    'share_right_accepted': True,
                }

                self.assertEqual(store, target_store)

        self.assertTrue(found, 'Did not find the share in the share list call')

        # lets try to get it back in detail

        url = reverse('share', kwargs={'share_id': new_share_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        target_store = {
            'id': UUID(new_share_id, version=4),
            'data': str(initial_data['data']),
            'data_nonce': initial_data['data_nonce'],
            'user_id': self.test_user_obj.id,
            'rights': {
                'grant': True,
                'read': True,
                'write': True,
            },
            'write_date': models.Share.objects.get(pk=new_share_id).write_date.isoformat()
        }

        self.assertEqual(response.data, target_store)

        # ok lets try to get the same share with a bad user

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # lets also check list view for another user

        url = reverse('share')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                              'Shares do not exist in list shares response')

        for store in response.data.get('shares', []):
            self.assertNotEqual(store.get('id', ''), new_share_id,
                                'Found our share in the list view of another user')

    def test_insert_share_failure_duplicate_link_id(self):
        """
        Tests to insert the share while reusing a the link id
        """

        url = reverse('share')

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '12c5f6b3-61cb-451b-bbc8-950215a01496',
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # And now lets try to reuse the link id
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_insert_share_into_share_without_write_permissions(self):
        """
        Tests to insert the share and check the rights to access it
        """

        # lets try to create a share

        url = reverse('share')

        self.test_user_share_right1_obj.write = False
        self.test_user_share_right1_obj.save()

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': 'a2546859-84a9-4340-b620-2d0989e253ef',
            'parent_share_id': self.test_share1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_insert_share_in_datastore(self):
        """
        Tests to insert the share into a datastore
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '996a29d9-aeb7-496a-864c-d6e1c350637b',
            'parent_datastore_id': self.test_datastore1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_insert_share_failure_parent_datastore_does_not_exist(self):
        """
        Tests to insert the share into a datastore that does not exist
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '47986868-5950-476f-b532-3ed3a80d515d',
            'parent_datastore_id': "2ac162b5-f388-46bb-9472-249e47f4fc17",
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_insert_share_failure_parent_datastore_belongs_other_user(self):
        """
        Tests to insert the share into a datastore that belongs to another user
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '47986868-5950-476f-b532-3ed3a80d515d',
            'parent_datastore_id': self.test_datastore2_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_insert_share_failure_parent_share_does_not_exist(self):
        """
        Tests to insert the share into a share that does not exist
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '47986868-5950-476f-b532-3ed3a80d515d',
            'parent_share_id': "4963cbb1-4772-4cd7-8997-2792f85b9555",
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_insert_share_with_no_data(self):
        """
        Tests to insert the share with no data
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '47986868-5950-476f-b532-3ed3a80d515d',
            'parent_share_id': self.test_share1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_insert_share_with_no_link_id(self):
        """
        Tests to insert the share with no link_id
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'parent_share_id': self.test_share1_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_insert_share_failure_without_parent_datastore_nor_share(self):
        """
        Tests to insert the share without a parent datastore nor share
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '47986868-5950-476f-b532-3ed3a80d515d',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UpdateShareTests(APITestCaseExtended):
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
            username=self.test_username,
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='101e54acafea8a138916e33fcc631364eba744c7f7f76ecd1741e421e2d54de5',
            is_email_active=True
        )

        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='f08ec82fa3ddd3f0948bcd2b7aa00ecca13412ab1263cfe76ab92a0bfb87d9c1',
            is_email_active=True
        )

        self.test_share2_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data=b"my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            creator_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            share_id=self.test_share2_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
        )
    def test_update_share(self):
        """
        Tests to update the share
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '47986868-5950-476f-b532-3ed3a80d515d',
            'parent_share_id': self.test_share1_obj.id,
        }
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_id', False), False,
                            'Share id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'Share id is no valid UUID')

        new_share_id = str(response.data.get('share_id'))

        # Initial share set, so lets update it

        url = reverse('share')

        updated_data = {
            'share_id': new_share_id,
            'data': "123456",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, updated_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # lets try to get it back in detail

        url = reverse('share', kwargs={'share_id': new_share_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        target_store = {
            'id': UUID(new_share_id, version=4),
            'data': str(updated_data['data']),
            'data_nonce': updated_data['data_nonce'],
            'user_id': self.test_user_obj.id,
            'rights': {
                'grant': True,
                'read': True,
                'write': True,
            },
            'write_date': models.Share.objects.get(pk=new_share_id).write_date.isoformat()
        }

        self.assertEqual(response.data, target_store)



class MoreUpdateShareTests(APITestCaseExtended):
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='dc7165dc8960960bf74058737849fcd3514d536a2513b6bd85d03802894efef9',
            is_email_active=True
        )

        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted = True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='2cdb1751d210edde10eaf10158070afbd2bd20917fe8a823a2a5e0cd85ac6574',
            is_email_active=True
        )
        self.test_share2_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data=b"my-data",
            data_nonce="12345"
        )
        self.test_share3_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data=b"my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share3_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted = True
        )

    def test_bad_formatted_uuid(self):
        """
        Tests to update a share with no valid uuid
        """

        url = reverse('share')

        initial_data = {
            'share_id': '3c2c0f4d'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_not_existing_share(self):
        """
        Tests to update a share with no valid uuid
        """

        url = reverse('share')

        initial_data = {
            'share_id': '93dd801d-e709-4e2a-b9bb-1e0ed582379c'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_no_rights_on_share(self):
        """
        Tests to update a share with no rights
        """

        url = reverse('share')

        initial_data = {
            'share_id': self.test_share2_obj.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_no_write_rights_on_share(self):
        """
        Tests to update a share with no rights
        """

        url = reverse('share')

        initial_data = {
            'share_id': self.test_share3_obj.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_write_data_to_database(self):
        """
        Tests to write data to database
        """

        url = reverse('share')

        data = {
            'share_id': str(self.test_share1_obj.id),
            'data': 'sdfvgibhsdf897',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        updated_share = models.Share.objects.get(pk=str(self.test_share1_obj.id))

        self.assertEqual(updated_share.data, data['data'].encode(),
                         'data was not saved proper')
        self.assertEqual(updated_share.data_nonce, data['data_nonce'],
                         'data_nonce was not saved proper')

    def test_delete_recoverycode(self):
        """
        Tests DELETE method on share
        """

        url = reverse('share')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


