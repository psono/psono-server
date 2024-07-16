from django.urls import reverse
from django.utils import timezone
from django.test.utils import override_settings
from django.contrib.auth.hashers import make_password
from django.conf import settings
from datetime import timedelta
import json
import os
import binascii

from rest_framework import status
from restapi import models

from .base import APITestCaseExtended

import random
import string

class LinkShareAccess(APITestCaseExtended):
    """
    Test to access a link share
    """

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
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
        self.test_secret_key_nonce3 = "f580cc9500ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
        self.test_private_key_nonce3 = "4398a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"

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
            user_sauce='07442887c295d119c2ceab107bf5cdefa0d19e674fcb50adc7f476d04878e2b0',
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            username=self.test_username2,
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='ecb4617eaa0aee3c49c237e55c5604c30161e42a727ebb95182065039ea3bd4e',
            is_email_active=True
        )

        self.test_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=b'12345',
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data=b"12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.secret_link_obj = models.Secret_Link.objects.create(
            link_id = '0493017f-47b0-446e-9a41-6533721ade71',
            secret_id = self.test_secret_obj.id,
            parent_datastore_id = self.test_datastore_obj.id,
            parent_share_id = None
        )

        self.test_secret2_obj = models.Secret.objects.create(
            user_id=self.test_user2_obj.id,
            data=b'12345',
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.shard1 = models.Fileserver_Shard.objects.create(
            title='Some Shard Title',
            description='Some Shard Description',
        )

        self.cluster1 = models.Fileserver_Cluster.objects.create(
            title='Some Fileserver Cluster Title',
            auth_public_key='abc',
            auth_private_key='abc',
            file_size_limit=0,
        )

        self.fileserver1 = models.Fileserver_Cluster_Members.objects.create(
            create_ip='127.0.0.1',
            fileserver_cluster=self.cluster1,
            key='abc',
            public_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            secret_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            url='https://fs01.example.com/fileserver',
            read=True,
            write=True,
            delete_capability=True,
            valid_till=timezone.now() + timedelta(seconds=30),
        )

        models.Fileserver_Cluster_Member_Shard_Link.objects.create(
            shard=self.shard1,
            member=self.fileserver1,
            read=True,
            write=True,
            delete_capability=True,
            ip_read_whitelist=json.dumps([]),
            ip_read_blacklist=json.dumps([]),
            ip_write_whitelist=json.dumps([]),
            ip_write_blacklist=json.dumps([]),
        )

        self.file = models.File.objects.create(
            shard=self.shard1,
            file_repository_id=None,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )


        self.file_link = models.File_Link.objects.create(
            link_id = '0e98f859-6134-49e9-9bc1-3face1401bdc',
            file_id = self.file.id,
            parent_datastore_id = self.test_datastore_obj.id,
            parent_share_id = None
        )

        self.link_share = models.Link_Share.objects.create(
            user=self.test_user_obj,
            secret=self.test_secret_obj,
            file_id=None,
            allowed_reads=True,
            public_title='A public title',
            node=b'kbixmnfhbzmelpujlulqtlulvcvptmauciygeyoipmlehhyuaizhqzzrtjhemdoi',
            node_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            passphrase=None,
            valid_till=None,
        )


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_get(self):
        """
        Tests PUT on link share access
        """

        url = reverse('link_share_access')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put(self):
        """
        Tests PUT on link share access to update a secret
        """

        self.link_share.allow_write = True
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        secret = models.Secret.objects.get(pk=self.test_secret_obj.id)

        self.assertEqual(secret.data.decode(), data['secret_data'])
        self.assertEqual(secret.data_nonce, data['secret_data_nonce'])


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_allowed_reads_being_decremented(self):
        """
        Tests PUT on link share access to update a secret and check that the allowed reads counter is decremented
        """

        self.link_share.allowed_reads = 2
        self.link_share.allow_write = True
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # ... should first decrement things
        self.assertTrue(models.Link_Share.objects.filter(pk=self.link_share.id, allowed_reads=1).exists())

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # ... and then delete it
        self.assertFalse(models.Link_Share.objects.filter(pk=self.link_share.id).exists())


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_link_share_not_valid_anymore(self):
        """
        Tests PUT on link share access that is not valid anymore
        """

        self.link_share.allow_write = True
        self.link_share.valid_till = timezone.now() - timedelta(seconds=1)
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_link_share_with_user_not_active_anymore(self):
        """
        Tests PUT on link share access where the creating user is not active anymore
        """

        self.link_share.allow_write = True
        self.link_share.save()
        self.link_share.user.is_active = False
        self.link_share.user.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_link_share_with_user_that_has_no_rights_anymore(self):
        """
        Tests PUT on link share access where the creating user is not active anymore
        """

        self.link_share.allow_write = True
        self.link_share.save()

        self.secret_link_obj.delete()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_link_share_no_operations_anymore(self):
        """
        Tests PUT on link share access that allows no further ops anymore
        """

        self.link_share.allow_write = True
        self.link_share.allowed_reads = 0  # This is the counter that handles writes when writes are enabled
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_link_with_passphrase(self):
        """
        Tests PUT on link share access successfully with a passphrase
        """

        self.link_share.allow_write = True
        self.link_share.passphrase = make_password("gbnfalasd")
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'passphrase': 'gbnfalasd',
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_link_share_no_passphrase(self):
        """
        Tests PUT on link share access without passphrase
        """

        self.link_share.allow_write = True
        self.link_share.passphrase = make_password("gbnfalasd")
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            #'passphrase': 'gbnfalasd',
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_link_share_wrong_passphrase(self):
        """
        Tests PUT on link share with the wrong passphrase
        """

        self.link_share.allow_write = True
        self.link_share.passphrase = make_password("gbnfalasd")
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'passphrase': 'asdfg',
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_link_share_id_not_exist(self):
        """
        Tests PUT on link share access that does not exist
        """

        self.link_share.allow_write = True
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': "3ab39f54-57f9-4b5d-a813-beb32a833ab3",
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_without_allow_write(self):
        """
        Tests PUT on link share access to update a secret
        """

        # self.link_share.allow_write = True
        # self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'secret_data': '12345',
            'secret_data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_success_with_secret(self):
        """
        Tests POST on link share access with a secret that is being shared
        """

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id)
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_success_check_read_count(self):
        """
        Tests POST on link share access with a secret and check that the read counter is incremented
        """

        self.link_share.allowed_reads = 2
        self.link_share.save()

        self.assertTrue(models.Secret.objects.filter(pk=self.test_secret_obj.id, read_count=0).exists())

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id)
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = json.loads(response.content)
        self.assertEqual(response_data['secret_read_count'], 1)

        self.assertTrue(models.Secret.objects.filter(pk=self.test_secret_obj.id, read_count=1).exists())

        # try again a second time
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = json.loads(response.content)
        self.assertEqual(response_data['secret_read_count'], 2)

        self.assertTrue(models.Secret.objects.filter(pk=self.test_secret_obj.id, read_count=2).exists())


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_success_check_read_count_with_allow_write(self):
        """
        Tests POST on link share access with a secret and check that the read counter is incremented even with allow write
        """

        self.link_share.allow_write = True
        self.link_share.allowed_reads = 1
        self.link_share.save()

        self.assertTrue(models.Secret.objects.filter(pk=self.test_secret_obj.id, read_count=0).exists())

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id)
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = json.loads(response.content)
        self.assertEqual(response_data['secret_read_count'], 1)

        self.assertTrue(models.Secret.objects.filter(pk=self.test_secret_obj.id, read_count=1).exists())

        # try again a second time
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = json.loads(response.content)
        self.assertEqual(response_data['secret_read_count'], 2)

        self.assertTrue(models.Secret.objects.filter(pk=self.test_secret_obj.id, read_count=2).exists())

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_success_with_file(self):
        """
        Tests POST on link share access with a file that is being shared
        """

        self.link_share.file_id = self.file.id
        self.link_share.secret_id = None
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id)
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.File_Transfer.objects.count(), 1)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_with_expired_link_share(self):
        """
        Tests POST on link share access with an already expired link share
        """

        self.link_share.valid_till = timezone.now() - timedelta(seconds=1)
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_user_has_been_disabled(self):
        """
        Tests POST on link share access where the user that created the link share has been disabled
        """

        self.test_user_obj.is_active = False
        self.test_user_obj.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_with_allowed_reads_already_used(self):
        """
        Tests POST on link share access with allowed reads already being used
        """

        self.link_share.allowed_reads = 0
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_with_allowed_reads_already_used_but_allow_write(self):
        """
        Tests POST on link share access with allowed reads already being used but allow read being true so reads are prevented if a write did happen for example
        """

        self.link_share.allow_write = True
        self.link_share.allowed_reads = 0
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_without_passphrase_while_passphrase_being_required(self):
        """
        Tests POST on link share access without providing a passphrase while a passphrase is required
        """

        self.link_share.passphrase = make_password("gbnfalasd")
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_with_not_matching_passphrase(self):
        """
        Tests POST on link share access with a passphrase that is wrong
        """

        self.link_share.passphrase = make_password("gbnfalasd")
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'passphrase': 'not passphrase',

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_for_link_share_without_file_id_nor_secret_id(self):
        """
        Tests POST on link share access for a link share that has no file nor secret id
        """

        self.link_share.secret_id = None
        self.link_share.file_id = None
        self.link_share.save()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'passphrase': 'not passphrase',

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_for_link_share_where_issuing_user_lost_privileges_to_secret(self):
        """
        Tests POST on link share access where the issuing user lost his privileges
        """

        self.secret_link_obj.delete()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'passphrase': 'not passphrase',

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_for_link_share_where_issuing_user_lost_privileges_to_file(self):
        """
        Tests POST on link share access where the issuing user lost his privileges
        """

        self.link_share.secret_id = None
        self.link_share.file_id = self.file.id
        self.link_share.save()

        self.file_link.delete()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'passphrase': 'not passphrase',

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_for_link_share_where_no_fileserver_being_able_to_serve_file(self):
        """
        Tests POST on link share access where no fileserver is available to serve the file
        """

        self.link_share.secret_id = None
        self.link_share.file_id = self.file.id
        self.link_share.save()

        self.fileserver1.delete()

        url = reverse('link_share_access')

        data = {
            'link_share_id': str(self.link_share.id),
            'passphrase': 'not passphrase',

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete(self):
        """
        Tests DELETE on link share access
        """

        url = reverse('link_share_access')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
