from django.urls import reverse

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models
from restapi.utils import encrypt_with_db_secret

import json

class ReadFileRepositoryRightTest(APITestCaseExtended):
    """
    Test to read file repository rights (GET)
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
            user_sauce='af8d7c6e835a4e378655e8e11fa0b09afc2f08acf0be1d71d9fa048a2b09d2eb',
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
            user_sauce='f2b5314ccdd726c3f4deabf5efccb0de5183796a9ecc691565aff2edf8c60249',
            is_email_active=True
        )


        self.file_repository = models.File_Repository.objects.create(
            title='Some Title',
            type='gcp_cloud_storage',
            data=encrypt_with_db_secret(json.dumps({})).encode(),
            active=True,
        )

        self.file_repository_right = models.File_Repository_Right.objects.create(
            user=self.test_user_obj,
            file_repository=self.file_repository,
            read=True,
            write=True,
            grant=True,
            accepted=True,
        )


    def test_read_all_success(self):
        """
        Tests to read all file repository rights
        """

        url = reverse('file_repository_right')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
    def test_read_all_without_authentication(self):
        """
        Tests to read all file repository rights without authentication
        """

        url = reverse('file_repository_right')

        data = {
        }

        # self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class CreateFileRepositoryRightTest(APITestCaseExtended):
    """
    Test to create a file repository right (PUT)
    """
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
            authkey="abc",
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='f3c0a6788364ab164d574b655ac2a90b8124d3a20fd341c38a24566188390d01',
            is_email_active=True
        )


        self.file_repository = models.File_Repository.objects.create(
            title='Some Title',
            type='gcp_cloud_storage',
            data=encrypt_with_db_secret(json.dumps({})).encode(),
            active=True,
        )

        self.file_repository_right = models.File_Repository_Right.objects.create(
            user=self.test_user_obj,
            file_repository=self.file_repository,
            read=True,
            write=True,
            grant=True,
            accepted=True,
        )


    def test_create_success(self):
        """
        Tests to create a file repository right
        """

        url = reverse('file_repository_right')

        data = {
            'user_id': str(self.test_user2_obj.id),
            'file_repository_id': str(self.file_repository.id),
            'read': True,
            'write': True,
            'grant': True,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        self.assertEqual(models.File_Repository_Right.objects.count(), 2)

    def test_create_without_grant(self):
        """
        Tests to create a file repository right without having grant permission
        """

        self.file_repository_right.grant = False
        self.file_repository_right.save()

        url = reverse('file_repository_right')

        data = {
            'user_id': str(self.test_user2_obj.id),
            'file_repository_id': str(self.file_repository.id),
            'read': True,
            'write': True,
            'grant': True,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_with_user_already_having_a_right(self):
        """
        Tests to create a file repository right for a user that already has a right
        """
        models.File_Repository_Right.objects.create(
            user=self.test_user2_obj,
            file_repository=self.file_repository,
            read=True,
            write=True,
            grant=True,
            accepted=True,
        )

        url = reverse('file_repository_right')

        data = {
            'user_id': str(self.test_user2_obj.id),
            'file_repository_id': str(self.file_repository.id),
            'read': True,
            'write': True,
            'grant': True,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_with_unknown_user(self):
        """
        Tests to create a file repository right for a user that doesn't exist
        """

        url = reverse('file_repository_right')

        data = {
            'user_id': 'be3b155f-dbaf-4201-836a-48c04a736b3b',
            'file_repository_id': str(self.file_repository.id),
            'read': True,
            'write': True,
            'grant': True,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_without_authentication(self):
        """
        Tests to create a file repository right without authentication
        """

        url = reverse('file_repository_right')

        data = {
            'user_id': str(self.test_user2_obj.id),
            'file_repository_id': str(self.file_repository.id),
            'read': True,
            'write': True,
            'grant': True,
        }

        #self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_without_authorization(self):
        """
        Tests to create a file repository right with a user that has no authorization
        """

        url = reverse('file_repository_right')

        data = {
            'user_id': str(self.test_user2_obj.id),
            'file_repository_id': str(self.file_repository.id),
            'read': True,
            'write': True,
            'grant': True,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UpdateFileRepositoryRightTest(APITestCaseExtended):
    """
    Test to update a file repository (POST)
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
            user_sauce='af8d7c6e835a4e378655e8e11fa0b09afc2f08acf0be1d71d9fa048a2b09d2eb',
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
            user_sauce='f2b5314ccdd726c3f4deabf5efccb0de5183796a9ecc691565aff2edf8c60249',
            is_email_active=True
        )


        self.file_repository = models.File_Repository.objects.create(
            title='Some Title',
            type='gcp_cloud_storage',
            data=encrypt_with_db_secret(json.dumps({})).encode(),
            active=True,
        )

        self.file_repository_right = models.File_Repository_Right.objects.create(
            user=self.test_user_obj,
            file_repository=self.file_repository,
            read=True,
            write=True,
            grant=True,
            accepted=True,
        )
        self.file_repository_right2 = models.File_Repository_Right.objects.create(
            user=self.test_user2_obj,
            file_repository=self.file_repository,
            read=False,
            write=False,
            grant=False,
            accepted=True,
        )


    def test_update_success(self):
        """
        Tests to update a file repository right successfully
        """

        url = reverse('file_repository_right')

        data = {
            'file_repository_right_id': str(self.file_repository_right2.id),
            'read': True,
            'write': True,
            'grant': True,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        file_repository_right = models.File_Repository_Right.objects.get(pk=self.file_repository_right2.id)

        self.assertTrue(file_repository_right.read)
        self.assertTrue(file_repository_right.write)
        self.assertTrue(file_repository_right.grant)

    def test_update_file_repository_right_that_doesnt_exist(self):
        """
        Tests to update a file repository right that doesn't exist
        """

        url = reverse('file_repository_right')

        data = {
            'file_repository_right_id': "bfd88f5b-9f28-4b54-97ed-74bac8763646",
            'read': True,
            'write': True,
            'grant': True,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_without_authentication(self):
        """
        Tests to update a file repository right without authentication
        """

        url = reverse('file_repository_right')

        data = {
            'file_repository_right_id': str(self.file_repository_right2.id),
            'read': True,
            'write': True,
            'grant': True,
        }

        # self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    def test_update_without_authorization(self):
        """
        Tests to update a file repository right without authorization
        """

        url = reverse('file_repository_right')

        data = {
            'file_repository_right_id': str(self.file_repository_right2.id),
            'read': True,
            'write': True,
            'grant': True,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class DeleteFileRepositoryRightTest(APITestCaseExtended):
    """
    Test to delete a file repository (DELETE)
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
            user_sauce='af8d7c6e835a4e378655e8e11fa0b09afc2f08acf0be1d71d9fa048a2b09d2eb',
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
            user_sauce='f2b5314ccdd726c3f4deabf5efccb0de5183796a9ecc691565aff2edf8c60249',
            is_email_active=True
        )


        self.file_repository = models.File_Repository.objects.create(
            title='Some Title',
            type='gcp_cloud_storage',
            data=encrypt_with_db_secret(json.dumps({})).encode(),
            active=True,
        )

        self.file_repository_right = models.File_Repository_Right.objects.create(
            user=self.test_user_obj,
            file_repository=self.file_repository,
            read=True,
            write=True,
            grant=True,
            accepted=True,
        )
        self.file_repository_right2 = models.File_Repository_Right.objects.create(
            user=self.test_user2_obj,
            file_repository=self.file_repository,
            read=False,
            write=False,
            grant=False,
            accepted=True,
        )


    def test_delete_success(self):
        """
        Tests to delete a file repository right successfully
        """

        url = reverse('file_repository_right')

        data = {
            'file_repository_right_id': self.file_repository_right2.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.File_Repository_Right.objects.count(), 1)

    def test_delete_without_authentication(self):
        """
        Tests to delete a file repository right without authentication
        """

        url = reverse('file_repository_right')

        data = {
            'file_repository_right_id': self.file_repository_right2.id,
        }

        # self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_without_authorization(self):
        """
        Tests to delete a file repository right without authorization
        """

        url = reverse('file_repository_right')

        data = {
            'file_repository_right_id': self.file_repository_right.id,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_own_right(self):
        """
        Tests to delete own file repository right, even so the user has no grant permission
        """

        url = reverse('file_repository_right')

        data = {
            'file_repository_right_id': self.file_repository_right2.id,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.File_Repository_Right.objects.count(), 1)

