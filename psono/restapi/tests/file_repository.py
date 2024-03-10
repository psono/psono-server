from django.urls import reverse
from django.test.utils import override_settings

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models
from restapi.utils import encrypt_with_db_secret

import json

class ReadFileRepositryTest(APITestCaseExtended):
    """
    Test to read file repositories (GET)
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
        Tests to read all file repositories
        """

        url = reverse('file_repository')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue('file_repositories' in response.data)

        file_repositories = response.data.get('file_repositories')

        self.assertEqual(len(file_repositories), 1)

        file_repository = file_repositories[0]

        self.assertEqual(file_repository.get('id'), str(self.file_repository.id))
        self.assertEqual(file_repository.get('title'), self.file_repository.title)
        self.assertEqual(file_repository.get('type'), self.file_repository.type)
        self.assertEqual(file_repository.get('active'), self.file_repository.active)
        self.assertEqual(file_repository.get('read'), self.file_repository_right.read)
        self.assertEqual(file_repository.get('write'), self.file_repository_right.write)
        self.assertEqual(file_repository.get('grant'), self.file_repository_right.grant)
        self.assertEqual(file_repository.get('accepted'), self.file_repository_right.accepted)
        self.assertEqual(file_repository.get('file_repository_right_id'), str(self.file_repository_right.id))
        self.assertTrue('data' not in file_repository)


    def test_read_single_success(self):
        """
        Tests to read a single file repositories
        """

        url = reverse('file_repository', kwargs={'file_repository_id': str(self.file_repository.id)})

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        file_repository = response.data

        self.assertEqual(file_repository.get('id'), str(self.file_repository.id))
        self.assertEqual(file_repository.get('title'), self.file_repository.title)
        self.assertEqual(file_repository.get('type'), self.file_repository.type)
        self.assertEqual(file_repository.get('active'), self.file_repository.active)
        self.assertEqual(file_repository.get('read'), self.file_repository_right.read)
        self.assertEqual(file_repository.get('write'), self.file_repository_right.write)
        self.assertEqual(file_repository.get('grant'), self.file_repository_right.grant)
        self.assertTrue('file_repository_rights' in file_repository)
        self.assertEqual(len(file_repository.get('file_repository_rights')), 1)


    def test_read_single_no_right(self):
        """
        Tests to read a single file repositories without any rights
        """

        url = reverse('file_repository', kwargs={'file_repository_id': str(self.file_repository.id)})

        data = {
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_read_single_that_does_not_exist(self):
        """
        Tests to read a single file repositories without any rights
        """

        url = reverse('file_repository', kwargs={'file_repository_id': '1fd3401a-cd3d-4904-b82b-c86befe45645'})

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_read_single_that_the_user_did_not_accept_the_right_for(self):
        """
        Tests to read a single file repositories without accepting the rights previously
        """

        self.file_repository_right.accepted = False
        self.file_repository_right.save()

        url = reverse('file_repository', kwargs={'file_repository_id': str(self.file_repository.id)})

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class CreateFileRepositryTest(APITestCaseExtended):
    """
    Test to create a file repository (PUT)
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='90272aaf01a2d525223f192aca069e7f5661b3a0f1b1a91f9b16d493fdf15295',
            is_email_active=True
        )


    def test_create_success_gcp(self):
        """
        Tests to create a file repository for gcp
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        self.assertEqual(models.File_Repository.objects.count(), 1)
        self.assertEqual(models.File_Repository_Right.objects.count(), 1)


    def test_create_success_aws(self):
        """
        Tests to create a file repository for aws
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'aws_s3',
            'aws_s3_bucket': 'abc',
            'aws_s3_region': 'abc',
            'aws_s3_access_key_id': 'abc',
            'aws_s3_secret_access_key': 'abc',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        self.assertEqual(models.File_Repository.objects.count(), 1)
        self.assertEqual(models.File_Repository_Right.objects.count(), 1)


    def test_create_failure_aws_no_bucket(self):
        """
        Tests to create a file repository for aws without a bucket
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'aws_s3',
            # 'aws_s3_bucket': 'abc',
            'aws_s3_region': 'abc',
            'aws_s3_access_key_id': 'abc',
            'aws_s3_secret_access_key': 'abc',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_aws_no_region(self):
        """
        Tests to create a file repository for aws without a region
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'aws_s3',
            'aws_s3_bucket': 'abc',
            # 'aws_s3_region': 'abc',
            'aws_s3_access_key_id': 'abc',
            'aws_s3_secret_access_key': 'abc',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_aws_no_access_key_id(self):
        """
        Tests to create a file repository for aws without an access key id
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'aws_s3',
            'aws_s3_bucket': 'abc',
            'aws_s3_region': 'abc',
            # 'aws_s3_access_key_id': 'abc',
            'aws_s3_secret_access_key': 'abc',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_aws_no_secret_access_key(self):
        """
        Tests to create a file repository for aws without a secret access key
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'aws_s3',
            'aws_s3_bucket': 'abc',
            'aws_s3_region': 'abc',
            'aws_s3_access_key_id': 'abc',
            # 'aws_s3_secret_access_key': 'abc',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_title(self):
        """
        Tests to create a file repository without a title
        """

        url = reverse('file_repository')

        data = {
            # 'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_empty_title(self):
        """
        Tests to create a file repository with an empty title
        """

        url = reverse('file_repository')

        data = {
            'title': '',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_type(self):
        """
        Tests to create a file repository without a type
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            # 'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_gcp_cloud_storage_bucket(self):
        """
        Tests to create a file repository without a gcp_cloud_storage_bucket
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            # 'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_gcp_cloud_storage_json_key(self):
        """
        Tests to create a file repository without a gcp_cloud_storage_json_key
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            # 'gcp_cloud_storage_json_key': '{}'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_no_json_as_gcp_cloud_storage_json_key(self):
        """
        Tests to create a file repository with no json as gcp_cloud_storage_json_key
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_failure_unknown_type(self):
        """
        Tests to create a file repository with an unknown type
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'UnKnOwN',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(ALLOWED_FILE_REPOSITORY_TYPES=[
        'azure_blob',
        # 'gcp_cloud_storage',
        'aws_s3',
        'do_spaces',
        'backblaze',
        # 'other_s3',
    ])
    def test_create_failure_not_allowed_type(self):
        """
        Tests to create a file repository with a not allowed type
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(ALLOWED_FILE_REPOSITORY_TYPES=['other_s3'])
    @override_settings(ALLOWED_OTHER_S3_ENDPOINT_URL_PREFIX=['https://allowed.s3.url.com/with-path'])
    def test_create_failure_not_allowed_other_s3_url(self):
        """
        Tests to create a file repository with a not allowed type
        """

        url = reverse('file_repository')

        data = {
            'title': 'Test file repository',
            'type': 'other_s3',
            'other_s3_bucket': 'abc',
            'other_s3_region': 'region',
            'other_s3_access_key_id': 'access-key-id',
            'other_s3_secret_access_key': 'secret-access-key',
            'other_s3_endpoint_url': 'https://not.allowed.com',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class UpdateFileRepositryTest(APITestCaseExtended):
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
            data=encrypt_with_db_secret(json.dumps({})),
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


    def test_update_success_gcp(self):
        """
        Tests to update a file repository successfully for gcp
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_update_success_aws(self):
        """
        Tests to update a file repository successfully for aws
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'aws_s3',
            'aws_s3_bucket': 'abc',
            'aws_s3_region': 'abc',
            'aws_s3_access_key_id': 'abc',
            'aws_s3_secret_access_key': 'abc',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_update_failure_aws_no_bucket(self):
        """
        Tests to update a file repository on aws without bucket
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'aws_s3',
            # 'aws_s3_bucket': 'abc',
            'aws_s3_region': 'abc',
            'aws_s3_access_key_id': 'abc',
            'aws_s3_secret_access_key': 'abc',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_aws_no_region(self):
        """
        Tests to update a file repository on aws without region
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'aws_s3',
            'aws_s3_bucket': 'abc',
            # 'aws_s3_region': 'abc',
            'aws_s3_access_key_id': 'abc',
            'aws_s3_secret_access_key': 'abc',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_aws_no_access_key_id(self):
        """
        Tests to update a file repository on aws without access key id
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'aws_s3',
            'aws_s3_bucket': 'abc',
            'aws_s3_region': 'abc',
            # 'aws_s3_access_key_id': 'abc',
            'aws_s3_secret_access_key': 'abc',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_aws_no_secret_access_key(self):
        """
        Tests to update a file repository on aws without secret access key
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'aws_s3',
            'aws_s3_bucket': 'abc',
            'aws_s3_region': 'abc',
            'aws_s3_access_key_id': 'abc',
            # 'aws_s3_secret_access_key': 'abc',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_without_write_rights(self):
        """
        Tests to update a file repository without write rights
        """

        self.file_repository_right.write = False
        self.file_repository_right.save()

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_without_accepted_rights(self):
        """
        Tests to update a file repository without accepted rights
        """

        self.file_repository_right.accepted = False
        self.file_repository_right.save()

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_without_any_rights(self):
        """
        Tests to update a file repository without any rights
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_no_title(self):
        """
        Tests to update a file repository without a title
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            # 'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_no_type(self):
        """
        Tests to update a file repository without a type
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            # 'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_no_gcp_cloud_storage_bucket(self):
        """
        Tests to update a file repository without a gcp_cloud_storage_bucket
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            # 'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_no_gcp_cloud_storage_json_key(self):
        """
        Tests to update a file repository without a gcp_cloud_storage_json_key
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            # 'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_no_json_as_gcp_cloud_storage_json_key(self):
        """
        Tests to update a file repository with no json as gcp_cloud_storage_json_key
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_failure_unknown_type(self):
        """
        Tests to update a file repository with an unknown type
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'UnKnOwN',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    @override_settings(ALLOWED_FILE_REPOSITORY_TYPES=[
        'azure_blob',
        # 'gcp_cloud_storage',
        'aws_s3',
        'do_spaces',
        'backblaze',
        # 'other_s3',
    ])
    def test_update_failure_not_allowed_type(self):
        """
        Tests to update a file repository with a type that is not allwoed
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'gcp_cloud_storage',
            'gcp_cloud_storage_bucket': 'abc',
            'gcp_cloud_storage_json_key': '{}',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    @override_settings(ALLOWED_FILE_REPOSITORY_TYPES=['other_s3'])
    @override_settings(ALLOWED_OTHER_S3_ENDPOINT_URL_PREFIX=['https://allowed.s3.url.com/with-path'])
    def test_update_failure_not_allowed_other_s3_url(self):
        """
        Tests to update a other s3 file repository with an url that is not allowed
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
            'title': 'Test file repository',
            'type': 'other_s3',
            'other_s3_bucket': 'abc',
            'other_s3_region': 'region',
            'other_s3_access_key_id': 'access-key-id',
            'other_s3_secret_access_key': 'secret-access-key',
            'other_s3_endpoint_url': 'https://not.allowed.com',
            'active': True
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class DeleteFileRepositryTest(APITestCaseExtended):
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
            data=encrypt_with_db_secret(json.dumps({})),
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


    def test_delete_success(self):
        """
        Tests to delete a file repository successfully
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.File_Repository.objects.count(), 0)
        self.assertEqual(models.File_Repository_Right.objects.count(), 0)


    def test_delete_failure_invalid_repository_id(self):
        """
        Tests to delete a file repository with an invalid repository id
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': 'eec32fc8-ffdc-497a-84d1-600e83875e5b',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_no_rights(self):
        """
        Tests to delete a file repository with no right
        """

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_not_accepted_right(self):
        """
        Tests to delete a file repository without accepting the right
        """

        self.file_repository_right.accepted = False
        self.file_repository_right.save()

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_without_grant_rights(self):
        """
        Tests to delete a file repository without grant rights
        """

        self.file_repository_right.grant = False
        self.file_repository_right.save()

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_failure_without_write_rights(self):
        """
        Tests to delete a file repository without write rights
        """

        self.file_repository_right.grant = False
        self.file_repository_right.save()

        url = reverse('file_repository')

        data = {
            'file_repository_id': self.file_repository.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
