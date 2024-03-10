from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models

import random
import string

BAD_URL='BAD_URL'

def mock_request_post(url, data=None, json=None, **kwargs):
    if url == BAD_URL:
        raise Exception


class UserCreateLinkShareTest(APITestCaseExtended):
    """
    Test to create a link share (PUT)
    """
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "b"
        self.test_email3 = "test3@example.com"
        self.test_email_bcrypt3 = "test3@example.com"
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
        self.test_secret_key_nonce2 = "f580cc9902ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce3 = "f580c29902ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d8d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce3 = "4228a9ab3d8d5d8643dfd4445adc30301b565ab650497fb9"

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
            user_sauce='6b84c6bca05de45714f224e4707fa4e02a59fa21b1e6539f5f3f35fdbf914022',
            is_email_active=True
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
            user_sauce='4b01f5914b95005b011442ff6a88039627909e77e67f84066973b22131958ac2',
            is_email_active=True
        )
        self.test_user3_obj = models.User.objects.create(
            email=self.test_email3,
            email_bcrypt=self.test_email_bcrypt3,
            username=self.test_username3,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce3,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce3,
            user_sauce='dd8e55859b0542320fc4c442cfa7d751ef16ffcabbbefd0129c10cdc0ea79b00',
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


    def test_create_link_share(self):
        """
        Tests to create a link share
        """

        url = reverse('link_share')

        data = {
            'secret_id': str(self.test_secret_obj.id),
            'node': '12345',
            'node_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'public_title': 'A public title',
            'allowed_reads': 1,
            'passphrase': '',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        self.assertEqual(models.Link_Share.objects.count(), 1)

    def test_create_link_share_without_secret_and_file(self):
        """
        Tests to create a link share without secret nor file
        """

        url = reverse('link_share')

        data = {
            # 'secret_id': str(self.test_secret_obj.id),
            'node': '12345',
            'node_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'public_title': 'A public title',
            'allowed_reads': 1,
            'passphrase': '',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_link_share_with_secret_without_permission(self):
        """
        Tests to create a link share for a secret that the user has no permission for
        """

        url = reverse('link_share')

        data = {
            'secret_id': str(self.test_secret2_obj.id),
            'node': '12345',
            'node_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'public_title': 'A public title',
            'allowed_reads': 1,
            'passphrase': '',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_link_share_with_valid_till_already_expired(self):
        """
        Tests to create a link share with a valid till that is already expired
        """

        url = reverse('link_share')

        data = {
            'secret_id': str(self.test_secret_obj.id),
            'node': '12345',
            'node_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'public_title': 'A public title',
            'allowed_reads': 1,
            'passphrase': '',
            'valid_till': timezone.now() - timedelta(seconds=1),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class UserGetLinkShareTest(APITestCaseExtended):
    """
    Test to get a link share (GET)
    """
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "b"
        self.test_email3 = "test3@example.com"
        self.test_email_bcrypt3 = "test3@example.com"
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
        self.test_secret_key_nonce2 = "f580cc9902ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce3 = "f580c29902ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d8d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce3 = "4228a9ab3d8d5d8643dfd4445adc30301b565ab650497fb9"

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
            user_sauce='6b84c6bca05de45714f224e4707fa4e02a59fa21b1e6539f5f3f35fdbf914022',
            is_email_active=True
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
            user_sauce='4b01f5914b95005b011442ff6a88039627909e77e67f84066973b22131958ac2',
            is_email_active=True
        )
        self.test_user3_obj = models.User.objects.create(
            email=self.test_email3,
            email_bcrypt=self.test_email_bcrypt3,
            username=self.test_username3,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce3,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce3,
            user_sauce='dd8e55859b0542320fc4c442cfa7d751ef16ffcabbbefd0129c10cdc0ea79b00',
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
            data=b'12345',
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

        self.test_secret2_obj = models.Secret.objects.create(
            user_id=self.test_user2_obj.id,
            data=b'12345',
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )


    def test_read_link_share_success(self):
        """
        Tests to read a specific link share successful
        """

        url = reverse('link_share', kwargs={'link_share_id': str(self.link_share.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_without_uuid_and_existing_link_shares(self):
        """
        Tests to get all link shares without specifying a uuid
        """

        url = reverse('link_share')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIn('link_shares', response.data)
        self.assertEqual(len(response.data['link_shares']), 1)


    def test_without_uuid_and_no_existing_link_shares(self):
        """
        Tests to get all link shares without specifying a uuid, while having no link shares
        """

        url = reverse('link_share')

        data = {}

        self.client.force_authenticate(user=self.test_user3_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIn('link_shares', response.data)
        self.assertEqual(len(response.data['link_shares']), 0)


    def test_with_not_existing_link_share(self):
        """
        Tests to get a specific link share without rights
        """

        url = reverse('link_share', kwargs={'link_share_id': 'cf84fbd5-c606-4d5b-aa96-88c68a06cde4'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserUpdateLinkShareTest(APITestCaseExtended):
    """
    Test to update a link share (POST)
    """

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
        self.test_secret_key_nonce2 = "f580cc9902ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d8d5d8643dfd4445adc30301b565ab650497fb9"

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
            user_sauce='8b32efae0a4940bafa236ee35ee975f71833860b7fa747d44659717b18719d84',
            is_email_active=True
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
            user_sauce='14f79675e9b28c25d633b0e4511beb041cca41da864bd36c94c67d60c1d3f716',
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
            data=b'12345',
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

        self.test_secret2_obj = models.Secret.objects.create(
            user_id=self.test_user2_obj.id,
            data=b'12345',
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )


    def test_success(self):
        """
        Tests to update a specific link share successful
        """

        url = reverse('link_share')

        data = {
            'link_share_id': str(self.link_share.id),
            'public_title': 'Another public title',
            'allowed_reads': 2,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        updated_link_share = models.Link_Share.objects.get(pk=self.link_share.id)

        self.assertEqual(updated_link_share.public_title, data['public_title'])


    def test_without_permission(self):
        """
        Tests to update a specific link share without permission
        """

        url = reverse('link_share')

        data = {
            'link_share_id': str(self.link_share.id),
            'public_title': 'Another public title',
            'allowed_reads': 2,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_with_valid_till_already_expired(self):
        """
        Tests to update a specific link share with a valid till that is already expired
        """

        url = reverse('link_share')

        data = {
            'link_share_id': str(self.link_share.id),
            'public_title': 'Another public title',
            'allowed_reads': 2,
            'valid_till': timezone.now() - timedelta(seconds=1),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


