from django.core.urlresolvers import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status

from restapi import models

from .base import APITestCaseExtended

import random
import string

class DatastoreTests(APITestCaseExtended):
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

    def test_list_datastores_without_credentials(self):
        """
        Tests if someone gets datastores without credentials
        """

        url = reverse('datastore')

        data = {}

        response = self.client.get(url, data, user=self.test_user_obj)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIsInstance(response.data.get('datastores', False), list,
                                 'We got some data even with a 401')

    def test_list_datastores(self):
        """
        Tests if the initial listing of datastores works
        """

        url = reverse('datastore')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('datastores', False), list,
                              'Datastores do not exist in list datastores response')
        self.assertEqual(len(response.data.get('datastores', False)), 0,
                         'Datastores hold already data, but should not contain any data at the beginning')

    def test_insert_datastore(self):
        """
        Tests to insert the datastore and check the rights to access it
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': "my-type",
            'description': "my-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('datastore_id', False), False,
                            'Datastore id does not exist in datastore PUT answer')
        self.assertIsUUIDString(str(response.data.get('datastore_id', '')),
                                'Datastore id is no valid UUID')

        new_datastore_id = str(response.data.get('datastore_id'))

        # lets try to get it back in the list

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('datastores', False), list,
                              'Datastores do not exist in list datastores response')
        self.assertGreater(len(response.data.get('datastores', False)), 0,
                           'Datastores hold some data')

        found = False

        for store in response.data.get('datastores', []):
            if store.get('id', '') == new_datastore_id:
                self.assertFalse(found,
                                 'Found our datastore twice in the returned list')
                found = True
                self.assertEqual(store, {
                    'id': new_datastore_id,
                    'type': initial_data['type'],
                    'description': initial_data['description'],
                    'is_default': True,
                })

        self.assertTrue(found, 'Did not find the datastore in the datastore list call')

        # lets try to get it back in detail

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {
            'data': initial_data['data'],
            'data_nonce': initial_data['data_nonce'],
            'type': initial_data['type'],
            'description': initial_data['description'],
            'secret_key': initial_data['secret_key'],
            'secret_key_nonce': initial_data['secret_key_nonce'],
            'is_default': True,
        })

        # ok lets try to get the same datastore with a bad user

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # lets also check list view for another user

        url = reverse('datastore')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('datastores', False), list,
                              'Datastores do not exist in list datastores response')

        for store in response.data.get('datastores', []):
            self.assertNotEqual(store.get('id', ''), new_datastore_id,
                                'Found our datastore in the list view of another user')

    def test_insert_datastore_with_duplicate_nonce(self):
        """
        Tests to insert the datastore and check the rights to access it
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': "my-type",
            'description': "my-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        initial_data = {
            'type': "my-type",
            'description': "my-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_insert_datastore_with_same_type_and_description(self):
        """
        Tests to insert the datastore with the same type and description twice
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': "my-test-type",
            'description': "my-test-description",
            'data': "12345",
            'data_nonce': 'a' + ''.join(random.choice(string.ascii_lowercase) for _ in range(63)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': 'b' + ''.join(random.choice(string.ascii_lowercase) for _ in range(63)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('datastore_id', False), False,
                            'Datastore id does not exist in datastore PUT answer')
        self.assertIsUUIDString(str(response.data.get('datastore_id', '')),
                                'Datastore id is no valid UUID')

        initial_data2 = {
            'type': "my-test-type",
            'description': "my-test-description",
            'data': "12345",
            'data_nonce': 'c' + ''.join(random.choice(string.ascii_lowercase) for _ in range(63)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': 'd' + ''.join(random.choice(string.ascii_lowercase) for _ in range(63)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data2)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_datastore(self):
        """
        Tests to update the datastore
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': "my-sexy-type",
            'description': "my-sexy-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('datastore_id', False), False,
                            'Datastore id does not exist in datastore PUT answer')
        self.assertIsUUIDString(str(response.data.get('datastore_id', '')),
                                'Datastore id is no valid UUID')

        new_datastore_id = str(response.data.get('datastore_id'))

        # Initial datastore set, so lets update it

        url = reverse('datastore')

        updated_data = {
            'datastore_id': new_datastore_id,
            'data': "123456",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, updated_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # lets try to get it back in detail

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {
            'type': initial_data['type'],
            'description': initial_data['description'],

            'data': updated_data['data'],
            'data_nonce': updated_data['data_nonce'],
            'secret_key': updated_data['secret_key'],
            'secret_key_nonce': updated_data['secret_key_nonce'],
            'is_default': True,
        })

    def test_update_datastore_no_datastore_id(self):
        """
        Tests to update the datastore with no datastore_id
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': "my-sexy-type",
            'description': "my-sexy-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('datastore_id', False), False,
                            'Datastore id does not exist in datastore PUT answer')
        self.assertIsUUIDString(str(response.data.get('datastore_id', '')),
                                'Datastore id is no valid UUID')

        new_datastore_id = str(response.data.get('datastore_id'))

        # Initial datastore set, so lets update it

        url = reverse('datastore')

        updated_data = {
            'data': "123456",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, updated_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('error'), 'IdNoUUID')


    def test_change_datastore_type_or_description(self):
        """
        Tests to update the datastore with a type or description which should not work, because its not allwed to change
        those.
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': "my-second-sexy-type",
            'description': "my-second-sexy-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('datastore_id', False), False,
                            'Datastore id does not exist in datastore PUT answer')
        self.assertIsUUIDString(str(response.data.get('datastore_id', '')),
                                'Datastore id is no valid UUID')

        new_datastore_id = str(response.data.get('datastore_id'))

        # Initial datastore set, so lets update it

        url = reverse('datastore')

        updated_data = {
            'datastore_id': new_datastore_id,
            'type': "my-try-to-change-the-type",
            'description': "my-try-to-change-the-description",
            'data': "123456",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, updated_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # lets try to get it back in detail

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {
            'type': initial_data['type'],
            'description': updated_data['description'],

            'data': updated_data['data'],
            'data_nonce': updated_data['data_nonce'],
            'secret_key': updated_data['secret_key'],
            'secret_key_nonce': updated_data['secret_key_nonce'],
            'is_default': True,
        })

    def test_change_datastore_with_no_permissions(self):
        """
        Tests to update the datastore with no permissions
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': "my-second-sexy-type",
            'description': "my-second-sexy-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_datastore_id = str(response.data.get('datastore_id'))

        # Initial datastore set, so lets update it

        url = reverse('datastore')

        updated_data = {
            'datastore_id': new_datastore_id,
            'type': "my-try-to-change-the-type",
            'description': "my-try-to-change-the-description",
            'data': "123456",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, updated_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete(self):
        """
        Tests to delete the datastore
        """

        url = reverse('datastore')

        initial_data = {
            'type': "my-second-sexy-type",
            'description': "my-second-sexy-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'is_default': False
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_datastore_id = str(response.data.get('datastore_id'))

        # And now lets try to delete it
        url = reverse('datastore')

        data = {
            'authkey': self.test_authkey,
            'datastore_id': new_datastore_id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_default_datastore(self):
        """
        Tests to delete the default datastore
        """

        url = reverse('datastore')

        initial_data = {
            'type': "my-second-sexy-type",
            'description': "my-second-sexy-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'is_default': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_datastore_id = str(response.data.get('datastore_id'))

        # And now lets try to delete it
        url = reverse('datastore')

        data = {
            'authkey': self.test_authkey,
            'datastore_id': new_datastore_id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_default_with_no_datastore_id(self):
        """
        Tests to delete the default datastore
        """

        url = reverse('datastore')

        initial_data = {
            'type': "my-second-sexy-type",
            'description': "my-second-sexy-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'is_default': False
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_datastore_id = str(response.data.get('datastore_id'))

        # And now lets try to delete it
        url = reverse('datastore')

        data = {
            'authkey': self.test_authkey,
            # Missing 'datastore_id': new_datastore_id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_default_with_no_authkey(self):
        """
        Tests to delete the default datastore
        """

        url = reverse('datastore')

        initial_data = {
            'type': "my-second-sexy-type",
            'description': "my-second-sexy-description",
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'is_default': False
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_datastore_id = str(response.data.get('datastore_id'))

        # And now lets try to delete it
        url = reverse('datastore')

        data = {
            # Missing 'authkey': self.test_authkey,
            'datastore_id': new_datastore_id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
