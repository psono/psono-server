from django.urls import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status
from .base import APITestCaseExtended
from ..utils import readbuffer
from restapi import models

import random
import string

class ReadHistory(APITestCaseExtended):
    """
    Test to read a specific history item of a secret (GET)
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
            authkey=make_password(self.test_authkey),
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='14f79675e9b28c25d633b0e4511beb041cca41da864bd36c94c67d60c1d3f716',
            is_email_active=True
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= readbuffer("12345"),
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )


        url = reverse('secret')

        data = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'data': '12345',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.secret_id = response.data['secret_id']

        self.test_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer('12345'),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.test_secret_history_obj = models.Secret_History.objects.create(
            user_id=self.test_user_obj.id,
            secret_id=self.test_secret_obj.id,
            data=readbuffer('12345'),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.secret_link_obj = models.Secret_Link.objects.create(
            link_id = '0493017f-47b0-446e-9a41-6533721ade71',
            secret_id = self.test_secret_obj.id,
            parent_datastore_id = self.test_datastore_obj.id,
            parent_share_id = None
        )

        self.share1 = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer("my-data"),
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.share1.id,
            read=False,
            write=True,
            grant=True,
            accepted = True
        )


    def test_put(self):
        """
        Tests PUT on secret_history
        """

        url = reverse('history', kwargs={'secret_history_id': str(self.test_secret_history_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_post(self):
        """
        Tests POST on secret_history
        """

        url = reverse('history', kwargs={'secret_history_id': str(self.test_secret_history_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_delete(self):
        """
        Tests DELETE on secret_history
        """

        url = reverse('history', kwargs={'secret_history_id': str(self.test_secret_history_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_read_history_of_secret_success(self):
        """
        Tests to read the history of a secret
        """

        url = reverse('history', kwargs={'secret_history_id': str(self.test_secret_history_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('create_date'), self.test_secret_history_obj.create_date)
        self.assertEqual(response.data.get('write_date'), self.test_secret_history_obj.write_date)
        self.assertEqual(response.data.get('data'), self.test_secret_history_obj.data.decode())
        self.assertEqual(response.data.get('data_nonce'), self.test_secret_history_obj.data_nonce)
        self.assertEqual(response.data.get('type'), self.test_secret_history_obj.type)
        self.assertEqual(response.data.get('callback_url'), self.test_secret_history_obj.callback_url)
        self.assertEqual(response.data.get('callback_user'), self.test_secret_history_obj.callback_user)
        self.assertEqual(response.data.get('callback_pass'), self.test_secret_history_obj.callback_pass)


    def test_read_history_of_secret_failure_does_not_exist(self):
        """
        Tests to read the history of a secret that does not exist
        """

        url = reverse('history', kwargs={'secret_history_id': '53d78f4f-0512-4cbf-9ecb-c75f3fe11c8c'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_read_history_of_secret_failure_with_no_permission(self):
        """
        Tests to read the history of a secret without any permission
        """

        url = reverse('history', kwargs={'secret_history_id': str(self.test_secret_history_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_read_history_of_secret_failure_with_no_read_permission(self):
        """
        Tests to read the history of a secret without read permission
        """

        self.secret_link_obj.parent_datastore_id = None
        self.secret_link_obj.parent_share = self.share1
        self.secret_link_obj.save()

        url = reverse('history', kwargs={'secret_history_id': str(self.test_secret_history_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

