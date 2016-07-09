from django.core.urlresolvers import reverse
from django.core import mail
from django.conf import settings
from django.contrib.auth.hashers import make_password

from rest_framework import status

from restapi import models

from base import APITestCaseExtended

import random
import string
import os

from uuid import UUID


class SystemTests(APITestCaseExtended):
    def test_smtp_server_running(self):
        import socket
        e = None
        try:
            socket.create_connection((settings.EMAIL_HOST, settings.EMAIL_PORT), None)
        except socket.error as e:
            pass

        self.assertIsNone(e, "SMTP server on %s with port %s is not running. The error returnd was %s" % (
        settings.EMAIL_HOST, settings.EMAIL_PORT, str(e)))

    def test_send_email(self):
        """
        Try to send a test email
        """

        mail.outbox = []

        successfull_delivered_messages = mail.send_mail('SMTP e-mail test', 'This is a test e-mail message.',
                                                        'info@sanso.pw', ['saschapfeiffer1337@gmail.com'],
                                                        fail_silently=False)

        self.assertEqual(successfull_delivered_messages, 1)

        # Test that one message has been sent.
        self.assertEqual(len(mail.outbox), 1)

        # Verify that the subject of the first message is correct.
        self.assertEqual(mail.outbox[0].subject, 'SMTP e-mail test')

    def test_smtp_credentials(self):

        # TODO write test to check smtp server credentials with SSL / TLS or whatever is configured
        pass

    def test_secret(self):
        secret = settings.SECRET_KEY

        self.assertIsNotNone(secret, 'Please specify a SECRET_KEY that is at least 32 chars long')
        self.assertGreater(len(secret), 0, 'The SECRET_KEY cannot be empty and should have at least 32 chars')
        self.assertGreater(len(secret), 31,
                           'Please use a minimum of 32 chars for the SECRET_KEY, you only have %s' % (len(secret),))
        self.assertNotEqual(secret, 'SOME SUPER SECRET KEY THAT SHOULD BE RANDOM AND 32 OR MORE DIGITS LONG',
                            'Please change the SECRET_KEY value')

    def test_activation_link_secret(self):
        secret = settings.ACTIVATION_LINK_SECRET

        self.assertIsNotNone(secret, 'Please specify a ACTIVATION_LINK_SECRET that is at least 32 chars long')
        self.assertGreater(len(secret), 0,
                           'The ACTIVATION_LINK_SECRET cannot be empty and should have at least 32 chars')
        self.assertGreater(len(secret), 31,
                           'Please use a minimum of 32 chars for the ACTIVATION_LINK_SECRET, you only have %s' % (
                           len(secret),))
        self.assertNotEqual(secret, 'SOME SUPER SECRET KEY THAT SHOULD BE RANDOM AND 32 OR MORE DIGITS LONG',
                            'Please change the ACTIVATION_LINK_SECRET value')

    def test_email_from(self):
        secret = settings.EMAIL_FROM

        self.assertIsNotNone(secret, 'Please specify a EMAIL_FROM settings value')
        self.assertGreater(len(secret), 0, 'Please specify a EMAIL_FROM settings value')
        self.assertNotEqual(secret, 'the-mail-for-for-example-useraccount-activations@test.com',
                            'Please change the EMAIL_FROM value')




class DatastoreTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email2 = "test2@example.com"
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=os.urandom(32).encode('hex'),
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=os.urandom(32).encode('hex'),
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

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        updated_data = {
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
        })

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

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        updated_data = {
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
            'description': initial_data['description'],

            'data': updated_data['data'],
            'data_nonce': updated_data['data_nonce'],
            'secret_key': updated_data['secret_key'],
            'secret_key_nonce': updated_data['secret_key_nonce'],
        })


class ShareTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email2 = "test2@example.com"
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=os.urandom(32).encode('hex'),
            is_email_active=True
        )

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
            grant=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=os.urandom(32).encode('hex'),
            is_email_active=True
        )

        self.test_share2_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            share_id=self.test_share2_obj.id,
            read=True,
            write=True,
            grant=True
        )

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
        response = self.client.put(url, initial_data)

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
                    'share_right_create_user_id': self.test_user_obj.id,
                    'share_right_create_user_email': self.test_user_obj.email,
                    'share_right_title': "",
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

        url = reverse('share', kwargs={'uuid': new_share_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        target_store = {
            'id': UUID(new_share_id, version=4),
            'data': str(initial_data['data']),
            'data_nonce': initial_data['data_nonce'],
            'user_id': self.test_user_obj.id,
            'user_share_rights': [{
                'user_id': self.test_user_obj.id,
                'grant': True,
                'read': True,
                'key_nonce': initial_data['key_nonce'],
                'key_type': initial_data['key_type'],
                'write': True,
                'key': initial_data['key'],
                'id': response.data['user_share_rights'][0]['id']
            }],
            'user_share_rights_inherited': []
        }

        self.assertEqual(response.data, target_store)

        # ok lets try to get the same share with a bad user

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

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
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_id', False), False,
                            'Datastore id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'Datastore id is no valid UUID')

        new_share_id = str(response.data.get('share_id'))

        # Initial share set, so lets update it

        url = reverse('share', kwargs={'uuid': new_share_id})

        updated_data = {
            'data': "123456",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, updated_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # lets try to get it back in detail

        url = reverse('share', kwargs={'uuid': new_share_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        target_store = {
            'id': UUID(new_share_id, version=4),
            'data': str(updated_data['data']),
            'data_nonce': updated_data['data_nonce'],
            'user_id': self.test_user_obj.id,
            'user_share_rights': [{
                'user_id': self.test_user_obj.id,
                'grant': True,
                'read': True,
                'key_nonce': initial_data['key_nonce'],
                'write': True,
                'key': initial_data['key'],
                'key_type': initial_data['key_type'],
                'id': response.data['user_share_rights'][0]['id']
            }],
            'user_share_rights_inherited': []
        }

        self.assertEqual(response.data, target_store)


class UserShareRightTest(APITestCaseExtended):
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email2 = "test2@example.com"
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=os.urandom(32).encode('hex'),
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=os.urandom(32).encode('hex'),
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
            grant=True
        )

        # and now insert our dummy share_right
        self.test_share_right1_ob = models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            title="Sexy Password",
            read=True,
            write=True,
            grant=True,
            user_id=str(self.test_user2_obj.id),
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
            grant=True
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
            grant=True
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
            'title': "Sexy Password",
            'read': True,
            'write': True,
            'grant': True,
            'user_id': str(self.test_user2_obj.id),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

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
            'title': "Sexy Password",
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
            'title': "Sexy Password",
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
            grant=False
        )
        test_user_share_rights = models.User_Share_Right.objects.create(
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            share_id=self.test_share1_obj.id,
            read=False,
            write=False,
            grant=False
        )

        self.assertEqual(models.User_Share_Right.objects.filter(pk=test_user_share_rights.id).count(), 1,
                         'Exactly one share right with this id should exist')

        url = reverse('share_right', kwargs={'uuid': str(test_user_share_rights.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_share_right_with_uuid(self):
        """
        Tests to delete something without uuid
        """

        url = reverse('share_right', kwargs={})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

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

        url = reverse('share_right', kwargs={'uuid': str(test_user_share_rights.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.User_Share_Right.objects.filter(pk=test_user_share_rights.id).count(), 0,
                         'Share right with this id should have been deleted')

