from django.core.urlresolvers import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status
from base import APITestCaseExtended

from restapi import models

import random
import string
import os

from uuid import UUID

class UserShareRightsTest(APITestCaseExtended):
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

        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='a2f3576a5089078a36418316a2c88f0fd3cc1b0d2a35fb49701aa03ee95fba33',
            is_email_active=True
        )


        # Lets first insert our first dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        # ... and our second dummy share with no grant rights
        self.test_share2_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data_2",
            data_nonce="12345_2"
        )

        models.User_Share_Right.objects.create(
            share_id=self.test_share2_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=False,
            accepted=True
        )

        # ... and our third dummy share with grant rights
        self.test_share3_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data_2",
            data_nonce="12345_2"
        )

        models.User_Share_Right.objects.create(
            share_id=self.test_share3_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )


    def test_post_share_rights(self):
        """
        Tests if the initial listing of share rights without valid share id
        """

        url = reverse('share_rights', kwargs={'uuid': 'cebcd1c4-baf6-441f-b97f-796ba6c95848'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_put_share_rights(self):
        """
        Tests if the initial listing of share rights without valid share id
        """

        url = reverse('share_rights', kwargs={'uuid': 'cebcd1c4-baf6-441f-b97f-796ba6c95848'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_list_shares_without_valid_share_id(self):
        """
        Tests if the initial listing of share rights without valid share id
        """

        url = reverse('share_rights', kwargs={'uuid': 'cebcd1c4-baf6-441f-b97f-796ba6c95848'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_shares_without_rights(self):
        """
        Tests if the initial listing of share rights without any rights for the specified share
        """

        url = reverse('share_rights', kwargs={'uuid': str(self.test_share1_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_shares_without_grant_rights(self):
        """
        Tests if the initial listing of share rights without grant rights for the specified share
        """

        url = reverse('share_rights', kwargs={'uuid': str(self.test_share2_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_shares(self):
        """
        Tests if the initial listing of share rights works
        """

        url = reverse('share_rights', kwargs={'uuid': str(self.test_share3_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get('id', False), False,
                            'id does not exist in answer')
        self.assertNotEqual(response.data.get('own_share_rights', False), False,
                            'own_share_rights does not exist in answer')
        self.assertNotEqual(response.data.get('user_share_rights', False), False,
                            'user_share_rights does not exist in answer')
        self.assertNotEqual(response.data.get('user_share_rights_inherited', False), False,
                            'user_share_rights_inherited does not exist in answer')

    #TODO Test actual database integrity of saved share rights