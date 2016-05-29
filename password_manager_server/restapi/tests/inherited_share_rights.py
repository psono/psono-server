from django.core.urlresolvers import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status
from base import APITestCaseExtended

from restapi import models

import random
import string
import os

from uuid import UUID


class UserShareRightsWithInheritedRightTest(APITestCaseExtended):
    """
    Test to read/create/grant any share right, when normal inherited rights exist (nor not exist)
    """
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email2 = "test2@example.com"
        self.test_email3 = "test3@example.com"
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

        self.test_user3_obj = models.User.objects.create(
            email=self.test_email3,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce3,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce3,
            user_sauce=os.urandom(32).encode('hex'),
            is_email_active=True
        )

        # Lets first insert our first dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        # ... and our second dummy share
        self.test_share2_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data_2",
            data_nonce="12345_2"
        )

    def test_list_share_right_with_inherited_rights(self):
        """
        Tests if the initial listing of share rights works with inherited rights
        """

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 0,
                         'Shares hold already data, but should not contain any data at the beginning but we already got '
                         + str(len(response.data.get('share_rights', False))))

        # now lets define rights for the first share for this user
        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # TODO define inherited rights
        return

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 2,
                         'Shares should contain 2 entries but got '
                         + str(len(response.data.get('share_rights', False))))

    def test_read_share_with_inherited_read_rights(self):
        """
        Tests read share with inherited read rights
        """

        # now lets define rights for the first share for this user
        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # TODO define inherited rights for test_share2_obj / test_share_right1_obj

        return

        # Then lets try to get it with the user which has defined rights for this share including read

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')

        self.assertEqual(len(response.data.get('share_rights', False)), 2,
                         'Exactly 2 share rights should exist for this user but we got '
                         + str(len(response.data.get('share_rights', False))))

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

        url = reverse('share', kwargs={'uuid': str(self.test_share2_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data.get('data', ''), self.test_share2_obj.data,
                         'Share should contain data and data should be equal to the original data')
        self.assertEqual(response.data.get('data_nonce', ''), self.test_share2_obj.data_nonce,
                         'Share should contain the data nonce and data should be equal to the original data nonce')

    def test_grant_share_right_with_inherited_grant_right(self):
        """
        Tests to insert the share right and check the rights to access it
        """

        # now lets define rights for the first share for this user
        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # lets try to create a share right for this share with a user with no rights

        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.test_share2_obj.id),
            'title': "Sexy Password",
            'read': True,
            'write': True,
            'grant': True,
            'user_id': str(self.test_user_obj.id),
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # TODO define inherited rights for test_share2_obj / test_share_right1_obj
        return

        # and we try again with inherited rights

        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.test_share2_obj.id),
            'title': "Sexy Password",
            'read': True,
            'write': True,
            'grant': True,
            'user_id': str(self.test_user_obj.id),
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_right_id', False), False,
                            'Share id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_right_id', '')),
                                'Share id is no valid UUID')


    def test_delete_share_right_with_inherited_grant_rights(self):
        """
        Tests to delete the share right with inherited grant rights
        """

        # now lets define rights for the first share for this user
        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        self.test_share_right2_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share2_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user3_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # no rights for user3 so far, so the query for share1 should fail
        url = reverse('share_right', kwargs={'uuid': str(self.test_share_right1_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user3_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


        # and now lets define inherited rights for test_share1_obj / test_share_right2_obj
        return

        # and now it should succeed
        url = reverse('share_right', kwargs={'uuid': str(self.test_share_right1_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user3_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.User_Share_Right.objects.filter(pk=self.test_share_right1_obj.id).count(), 0,
                         'Share right with this id should have been deleted')


#
# class UserInheritedShareRightsWithRightTest(APITestCaseExtended):
#     """
#     Test to read/create/grant any inherited right, when normal share rights exist (nor not exist)
#     """
#     def setUp(self):
#         self.test_email = "test@example.com"
#         self.test_email2 = "test2@example.com"
#         self.test_email3 = "test3@example.com"
#         self.test_password = "myPassword"
#         self.test_authkey = "c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
#                             "123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
#         self.test_public_key = "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
#         self.test_secret_key = "a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
#         self.test_secret_key_enc = "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
#                                    "996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
#                                    "571a48eb"
#         self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
#         self.test_secret_key_nonce2 = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
#         self.test_secret_key_nonce3 = "f680cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
#         self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
#         self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
#                                     "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
#                                     "a74b9b2452"
#         self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
#         self.test_private_key_nonce2 = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
#         self.test_private_key_nonce3 = "4398a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
#
#         self.test_user_obj = models.User.objects.create(
#             email=self.test_email,
#             authkey=make_password(self.test_authkey),
#             public_key=self.test_public_key,
#             private_key=self.test_private_key_enc,
#             private_key_nonce=self.test_private_key_nonce,
#             secret_key=self.test_secret_key_enc,
#             secret_key_nonce=self.test_secret_key_nonce,
#             user_sauce=os.urandom(32).encode('hex'),
#             is_email_active=True
#         )
#
#         self.test_user2_obj = models.User.objects.create(
#             email=self.test_email2,
#             authkey=make_password(self.test_authkey),
#             public_key=self.test_public_key,
#             private_key=self.test_private_key_enc,
#             private_key_nonce=self.test_private_key_nonce2,
#             secret_key=self.test_secret_key_enc,
#             secret_key_nonce=self.test_secret_key_nonce2,
#             user_sauce=os.urandom(32).encode('hex'),
#             is_email_active=True
#         )
#
#         self.test_user3_obj = models.User.objects.create(
#             email=self.test_email3,
#             authkey=make_password(self.test_authkey),
#             public_key=self.test_public_key,
#             private_key=self.test_private_key_enc,
#             private_key_nonce=self.test_private_key_nonce3,
#             secret_key=self.test_secret_key_enc,
#             secret_key_nonce=self.test_secret_key_nonce3,
#             user_sauce=os.urandom(32).encode('hex'),
#             is_email_active=True
#         )
#
#         # Lets first insert our first dummy share
#         self.test_share1_obj = models.Share.objects.create(
#             user_id=self.test_user_obj.id,
#             data="my-data",
#             data_nonce="12345"
#         )
#
#         # ... and our second dummy share
#         self.test_share2_obj = models.Share.objects.create(
#             user_id=self.test_user_obj.id,
#             data="my-data_2",
#             data_nonce="12345_2"
#         )
#
#     def test_grant_inherited_share_right_with_grant_right(self):
#         """
#         Tests to insert an inherited share right based on grant share rights
#         """
#
#         # user1 share1 r-g
#         self.test_share_right1_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share1_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user_obj.id,
#             read=True,
#             write=False,
#             grant=True
#         )
#
#         # user2 share1 rwg
#         self.test_share_right2_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share1_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user2_obj.id,
#             read=True,
#             write=True,
#             grant=True
#         )
#
#         # lets try to create an inherited share right for share2
#         url = reverse('share_right_inherit')
#
#         initial_data = {
#             'share_right_id': str(self.test_share_right2_obj.id),
#             'share_id': str(self.test_share2_obj.id)
#         }
#
#         self.client.force_authenticate(user=self.test_user_obj)
#         response = self.client.put(url, initial_data)
#
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
#
#         # and now lets define some rights for user1 on share2
#         # user1 share2 r-g
#         self.test_share_right3_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share2_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user_obj.id,
#             read=True,
#             write=False,
#             grant=True # mandatory for this test
#         )
#
#         # and we try again to create an inherited share right for share2
#         url = reverse('share_right_inherit')
#
#         initial_data = {
#             'share_right_id': str(self.test_share_right2_obj.id),
#             'share_id': str(self.test_share2_obj.id)
#         }
#
#         self.client.force_authenticate(user=self.test_user_obj)
#         response = self.client.put(url, initial_data)
#
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#
#     def test_delete_inherited_share_right_with_grant_right(self):
#         """
#         Tests to delete an inherited share right based on grant share rights
#         """
#
#         # user1 share1 r-g
#         self.test_share_right1_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share1_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user_obj.id,
#             read=True,
#             write=False,
#             grant=True
#         )
#
#         # user2 share1 rwg
#         self.test_share_right2_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share1_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user2_obj.id,
#             read=True,
#             write=True,
#             grant=True
#         )
#
#         # TODO user2 share2 (inherited rwg) for test_share2_obj / test_share_right2_obj
#         return
#
#         # lets try to delete an inherited share right for share2
#         url = reverse('share_right_inherit')
#
#         initial_data = {
#             'share_right_id': str(self.test_share_right2_obj.id),
#             'share_id': str(self.test_share2_obj.id)
#         }
#
#         self.client.force_authenticate(user=self.test_user_obj)
#         response = self.client.delete(url, initial_data)
#
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
#
#         # and now lets define some rights for user1 on share2
#         # user1 share2 r-g
#         self.test_share_right3_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share2_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user_obj.id,
#             read=True,
#             write=False,
#             grant=True # mandatory for this test
#         )
#
#         # and we try again to create an inherited share right for share2
#         url = reverse('share_right_inherit')
#
#         initial_data = {
#             'share_right_id': str(self.test_share_right2_obj.id),
#             'share_id': str(self.test_share2_obj.id)
#         }
#
#         self.client.force_authenticate(user=self.test_user_obj)
#         response = self.client.delete(url, initial_data)
#
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#
#         # TODO check if it really has been deleted
#
#
#
# class UserInheritedShareRightsWithInheritedRightTest(APITestCaseExtended):
#     """
#     Test to read/create/grant any inherited right, when normal share rights exist (nor not exist)
#     """
#     def setUp(self):
#         self.test_email = "test@example.com"
#         self.test_email2 = "test2@example.com"
#         self.test_email3 = "test3@example.com"
#         self.test_password = "myPassword"
#         self.test_authkey = "c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
#                             "123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
#         self.test_public_key = "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
#         self.test_secret_key = "a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
#         self.test_secret_key_enc = "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
#                                    "996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
#                                    "571a48eb"
#         self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
#         self.test_secret_key_nonce2 = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
#         self.test_secret_key_nonce3 = "f680cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
#         self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
#         self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
#                                     "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
#                                     "a74b9b2452"
#         self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
#         self.test_private_key_nonce2 = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
#         self.test_private_key_nonce3 = "4398a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
#
#         self.test_user_obj = models.User.objects.create(
#             email=self.test_email,
#             authkey=make_password(self.test_authkey),
#             public_key=self.test_public_key,
#             private_key=self.test_private_key_enc,
#             private_key_nonce=self.test_private_key_nonce,
#             secret_key=self.test_secret_key_enc,
#             secret_key_nonce=self.test_secret_key_nonce,
#             user_sauce=os.urandom(32).encode('hex'),
#             is_email_active=True
#         )
#
#         self.test_user2_obj = models.User.objects.create(
#             email=self.test_email2,
#             authkey=make_password(self.test_authkey),
#             public_key=self.test_public_key,
#             private_key=self.test_private_key_enc,
#             private_key_nonce=self.test_private_key_nonce2,
#             secret_key=self.test_secret_key_enc,
#             secret_key_nonce=self.test_secret_key_nonce2,
#             user_sauce=os.urandom(32).encode('hex'),
#             is_email_active=True
#         )
#
#         self.test_user3_obj = models.User.objects.create(
#             email=self.test_email3,
#             authkey=make_password(self.test_authkey),
#             public_key=self.test_public_key,
#             private_key=self.test_private_key_enc,
#             private_key_nonce=self.test_private_key_nonce3,
#             secret_key=self.test_secret_key_enc,
#             secret_key_nonce=self.test_secret_key_nonce3,
#             user_sauce=os.urandom(32).encode('hex'),
#             is_email_active=True
#         )
#
#         # Lets first insert our first dummy share
#         self.test_share1_obj = models.Share.objects.create(
#             user_id=self.test_user_obj.id,
#             data="my-data",
#             data_nonce="12345"
#         )
#
#         # ... and our second dummy share
#         self.test_share2_obj = models.Share.objects.create(
#             user_id=self.test_user_obj.id,
#             data="my-data_2",
#             data_nonce="12345_2"
#         )
#
#     def test_grant_inherited_share_right_with_grant_right(self):
#         """
#         Tests to insert an inherited share right based on grant share rights
#         """
#
#         # user1 share1 r-g
#         self.test_share_right1_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share1_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user_obj.id,
#             read=True,
#             write=False,
#             grant=True
#         )
#
#         # user2 share1 rwg
#         self.test_share_right2_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share1_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user2_obj.id,
#             read=True,
#             write=True,
#             grant=True
#         )
#
#         # lets try to create an inherited share right for share2
#         url = reverse('share_right_inherit')
#
#         initial_data = {
#             'share_right_id': str(self.test_share_right2_obj.id),
#             'share_id': str(self.test_share2_obj.id)
#         }
#
#         self.client.force_authenticate(user=self.test_user_obj)
#         response = self.client.put(url, initial_data)
#
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
#
#         # TODO and now lets define some inherited rights for user1 on share2
#         # user1 share2 r-g for test_share2_obj / test_share_right1_obj
#         return
#
#         # and we try again to create an inherited share right for share2
#         url = reverse('share_right_inherit')
#
#         initial_data = {
#             'share_right_id': str(self.test_share_right2_obj.id),
#             'share_id': str(self.test_share2_obj.id)
#         }
#
#         self.client.force_authenticate(user=self.test_user_obj)
#         response = self.client.put(url, initial_data)
#
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#
#     def test_delete_inherited_share_right_with_grant_right(self):
#         """
#         Tests to delete an inherited share right based on grant share rights
#         """
#
#         # user1 share1 r-g
#         self.test_share_right1_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share1_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user_obj.id,
#             read=True,
#             write=False,
#             grant=True
#         )
#
#         # user2 share1 rwg
#         self.test_share_right2_obj = models.User_Share_Right.objects.create(
#             share_id=self.test_share1_obj.id,
#             owner_id=self.test_user_obj.id,
#             user_id=self.test_user2_obj.id,
#             read=True,
#             write=True,
#             grant=True
#         )
#
#         # TODO user2 share2 (inherited rwg) for test_share2_obj / test_share_right2_obj
#         return
#
#         # lets try to delete an inherited share right for share2
#         url = reverse('share_right_inherit')
#
#         initial_data = {
#             'share_right_id': str(self.test_share_right2_obj.id),
#             'share_id': str(self.test_share2_obj.id)
#         }
#
#         self.client.force_authenticate(user=self.test_user_obj)
#         response = self.client.delete(url, initial_data)
#
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
#
#
#         # TODO  now lets define some inherited rights for user1 on share2
#         # user1 share2 r-g for test_share2_obj / test_share_right1_obj
#         return
#
#         # and we try again to create an inherited share right for share2
#         url = reverse('share_right_inherit')
#
#         initial_data = {
#             'share_right_id': str(self.test_share_right2_obj.id),
#             'share_id': str(self.test_share2_obj.id)
#         }
#
#         self.client.force_authenticate(user=self.test_user_obj)
#         response = self.client.delete(url, initial_data)
#
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#
#         #TODO db check if it really has been deleted

