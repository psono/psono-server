from django.urls import reverse
from django.contrib.auth.hashers import make_password
from django.conf import settings

from rest_framework import status
from .base import APITestCaseExtended
from ..utils import readbuffer
from restapi import models

import json
import random
import string
import os
import binascii


class MetadataShareTest(APITestCaseExtended):
    """
    Test to read the metadata of a share
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
            authkey=make_password(self.test_authkey),
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
            authkey=make_password(self.test_authkey2),
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description="my-description",
            data=readbuffer("12345"),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.share_link_id = '1515a857-0bb9-46e0-9a84-97787b3d8ec6'
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer("my-data"),
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        self.link_id = '04f5a857-0bb9-46e0-9a84-97787b3d8ed5'

        self.test_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer('12345'),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.secret_link_obj = models.Secret_Link.objects.create(
            link_id=self.link_id,
            secret_id=self.test_secret_obj.id,
            parent_datastore_id=None,
            parent_share_id=self.test_share1_obj.id
        )

        models.Share_Tree.objects.create(
            share_id=self.test_share1_obj.id,
            parent_datastore_id=self.test_datastore_obj.id,
            path=str(self.share_link_id).replace("-", "")
        )

        self.share_link2_id = '2626a857-0bb9-46e0-9a84-97787b3d8ed7'
        self.test_share2_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer("my-data"),
            data_nonce="12345"
        )
        models.Share_Tree.objects.create(
            share_id=self.test_share2_obj.id,
            parent_share_id=self.test_share1_obj.id,
            path=str(self.share_link2_id).replace("-", "")
        )

    def test_read_metadata_share(self):
        """
        Tests to read the metadata of a share successfully
        """

        url = reverse('metadata_share', kwargs={'share_id': self.test_share1_obj.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(json.loads(response.content), {
            "write_date": self.test_share1_obj.write_date.isoformat(),
            "shares": [{
                "id": str(self.test_share2_obj.id),
                "write_date": self.test_share2_obj.write_date.isoformat(),
            }],
            "secrets": [{
                "id": str(self.test_secret_obj.id),
                "write_date": self.test_secret_obj.write_date.isoformat(),
            }]
        })

    def test_read_metadata_share_not_existing_share_id(self):
        """
        Tests to read the metadata of a share that doesn't exist
        """

        url = reverse('metadata_share', kwargs={'share_id': '1c70f736-3baa-47a5-9c38-dc0f164857ad'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_metadata_share_unauthenticated(self):
        """
        Tests to read the metadata of a share unauthenticated
        """

        url = reverse('metadata_share', kwargs={'share_id': self.test_share1_obj.id})

        data = {}

        # self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_read_metadata_share_unauthorized(self):
        """
        Tests to read the metadata of a share unauthorized
        """

        url = reverse('metadata_share', kwargs={'share_id': self.test_share1_obj.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
