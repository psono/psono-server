from django.test import TestCase

from restapi.utils import authenticate, yubikey_authenticate, yubikey_get_yubikey_id, calculate_user_rights_on_share, get_datastore, is_allowed_url
from restapi.utils import encrypt_secret, decrypt_secret
from restapi import models

import nacl.encoding
from uuid import uuid4
from mock import patch
import random
import string


def yubico_verify_true(yubikey_otp):
    """
    Yubico verify function that will always return True
    
    :param yubikey_otp: Yubikey OTP
    :type yubikey_otp: str
    :return: True
    :rtype: Boolean
    """

    # Take exactly 1 argument which we will happily ignore afterwards
    assert yubikey_otp

    return True


class TestUtils(TestCase):
    def test_authenticate_with_no_authkey(self):
        """
        Test authentication without authkey
        """
        self.assertEqual(authenticate('asdf', False, False), (False, 'AUTHKEY_NOT_PROVIDED'))

    def test_authenticate_with_no_username_nor_user_object(self):
        """
        Test authentication without username nor user object
        """
        self.assertEqual(authenticate(False, False, 'asdf'), (False, 'USER_NOT_PROVIDED'))

    def test_authenticate_with_wrong_username(self):
        """
        Test authentication with wrong username
        """
        self.assertEqual(authenticate('narf', False, 'asdf'), (False, 'USER_NOT_FOUND'))

    @patch('restapi.utils.yubikey.settings', YUBIKEY_CLIENT_ID='123', YUBIKEY_SECRET_KEY='T3VoIHlvdSBmb3VuZCBtZT8=')
    @patch('restapi.utils.yubikey.Yubico.verify', side_effect=yubico_verify_true)
    def test_yubikey_authenticate_works(self, settings_fct, yubico_verify_true_fct):
        self.assertTrue(yubikey_authenticate(5))

    @patch('restapi.utils.yubikey.settings', YUBIKEY_CLIENT_ID=None, YUBIKEY_SECRET_KEY='T3VoIHlvdSBmb3VuZCBtZT8=')
    def test_yubikey_authenticate_client_id_none(self, settings_fct):
        self.assertIsNone(yubikey_authenticate(5))

    @patch('restapi.utils.yubikey.settings', YUBIKEY_CLIENT_ID='123', YUBIKEY_SECRET_KEY=None)
    def test_yubikey_authenticate_secret_key_none(self, settings_fct):
        self.assertIsNone(yubikey_authenticate(5))

    def test_yubikey_authenticate_secret_key_none_success(self):
        self.assertEqual(yubikey_get_yubikey_id('iuhsrgknjbfjbfdkljbfdjiufiojfd'), 'iuhsrgknjbfj')

class TestVariousUtils(TestCase):
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

        self.test_datastore1_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= b"12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_datastore2_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-second-type",
            description= "my-description",
            data= b"12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

    def test_get_datastore_get_all_datastores_of_user(self):
        self.assertEqual(len(get_datastore(user=self.test_user_obj)), 2)

    def test_get_datastore_get_all_datastores_of_user_without_datastores(self):
        self.assertEqual(len(get_datastore(user=self.test_user2_obj)), 0)

    def test_get_datastore_get_all_datastores_without_user_nor_datastores(self):
        self.assertEqual(get_datastore(), None)

    def test_get_datastore_get_single_datastore(self):
        self.assertEqual(get_datastore(datastore_id=self.test_datastore1_obj.id), self.test_datastore1_obj)

    def test_get_datastore_get_single_datastore_that_does_not_exist(self):
        self.assertEqual(get_datastore(datastore_id=uuid4()), None)
    def test_decrypt_secret(self):
        hashing_params = models.default_hashing_parameters()

        decrypted_secret = decrypt_secret(
            nacl.encoding.HexEncoder.decode(b'dc7173d3e66cfda6057f16c752953aa91c452eb8df042b7a'),
            nacl.encoding.HexEncoder.decode(b'f09293db1a4d875c7cfb939e2e83c2c0c9455de898e9b745'),
            "myPassword",
            "userSauce".encode(),
            hashing_params['u'],
            hashing_params['r'],
            hashing_params['p'],
            hashing_params['l'],
        )

        self.assertEqual(decrypted_secret.decode(), "mySecret")

    def test_encrypt_secret(self):
        hashing_params = models.default_hashing_parameters()

        data, nonce = encrypt_secret(
            "mySecret".encode(),
            "myPassword",
            "userSauce".encode(),
            hashing_params['u'],
            hashing_params['r'],
            hashing_params['p'],
            hashing_params['l'],
        )

        decrypted_secret = decrypt_secret(
            nacl.encoding.HexEncoder.decode(data),
            nacl.encoding.HexEncoder.decode(nonce),
            "myPassword",
            "userSauce".encode(),
            hashing_params['u'],
            hashing_params['r'],
            hashing_params['p'],
            hashing_params['l'],
        )

        self.assertEqual(decrypted_secret.decode(), "mySecret")






class TestCalculateShareRightsOnShare(TestCase):

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

        self.user1 = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='dc7165dc8960960bf74058737849fcd3514d536a2513b6bd85d03802894efef9',
            is_email_active=True
        )

        self.user2 = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='2cdb1751d210edde10eaf10158070afbd2bd20917fe8a823a2a5e0cd85ac6574',
            is_email_active=True
        )

        self.group1 = models.Group.objects.create(
            name="Group Name",
            public_key=b"my-data",
        )

        self.share1 = models.Share.objects.create(
            user_id=self.user1.id,
            data=b"my-data",
            data_nonce="12345"
        )
        self.share2 = models.Share.objects.create(
            user_id=self.user2.id,
            data=b"my-data",
            data_nonce="12345"
        )
        self.share3 = models.Share.objects.create(
            user_id=self.user2.id,
            data=b"my-data",
            data_nonce="12345"
        )

        # models.User_Share_Right.objects.create(
        #     creator_id=self.user1.id,
        #     user_id=self.user1.id,
        #     share_id=self.share3.id,
        #     read=True,
        #     write=False,
        #     grant=True,
        #     accepted = True
        # )

        # models.User_Share_Right.objects.create(
        #     creator_id=self.test_user_obj.id,
        #     user_id=self.test_user_obj.id,
        #     share_id=self.test_share1_obj.id,
        #     read=True,
        #     write=True,
        #     grant=True,
        #     accepted = True
        # )

    def test_no_rights(self):
        self.assertEqual(
            calculate_user_rights_on_share(self.user1.id, self.share1.id),
            {'read': False, 'grant': False, 'write': False}
        )

    def test_direct_user_rights(self):

        models.User_Share_Right.objects.create(
            creator_id=self.user1.id,
            user_id=self.user1.id,
            share_id=self.share1.id,
            read=True,
            write=True,
            grant=True,
            accepted = True
        )

        self.assertEqual(
            calculate_user_rights_on_share(self.user1.id, self.share1.id),
            {'read': True, 'grant': True, 'write': True}
        )

    def test_direct_user_rights_not_accepted(self):

        models.User_Share_Right.objects.create(
            creator_id=self.user1.id,
            user_id=self.user1.id,
            share_id=self.share1.id,
            read=True,
            write=True,
            grant=True,
            accepted = None
        )

        self.assertEqual(
            calculate_user_rights_on_share(self.user1.id, self.share1.id),
            {'read': False, 'grant': False, 'write': False}
        )

    def test_direct_user_rights_declined(self):

        models.User_Share_Right.objects.create(
            creator_id=self.user1.id,
            user_id=self.user1.id,
            share_id=self.share1.id,
            read=True,
            write=True,
            grant=True,
            accepted = False
        )

        self.assertEqual(
            calculate_user_rights_on_share(self.user1.id, self.share1.id),
            {'read': False, 'grant': False, 'write': False}
        )

    def test_direct_group_rights(self):

        models.User_Group_Membership.objects.create(
            creator_id=self.user1.id,
            user_id=self.user1.id,
            group_id=self.group1.id,
            accepted=True
        )

        models.Group_Share_Right.objects.create(
            creator_id=self.user1.id,
            share_id=self.share1.id,
            group_id=self.group1.id,
            read=True,
            write=True,
            grant=True,
        )

        self.assertEqual(
            calculate_user_rights_on_share(self.user1.id, self.share1.id),
            {'read': True, 'grant': True, 'write': True}
        )

    def test_direct_group_right_not_accepted(self):

        models.User_Group_Membership.objects.create(
            creator_id=self.user1.id,
            user_id=self.user1.id,
            group_id=self.group1.id,
            accepted=None
        )

        models.Group_Share_Right.objects.create(
            creator_id=self.user1.id,
            share_id=self.share1.id,
            group_id=self.group1.id,
            read=True,
            write=True,
            grant=True,
        )

        self.assertEqual(
            calculate_user_rights_on_share(self.user1.id, self.share1.id),
            {'read': False, 'grant': False, 'write': False}
        )

    def test_direct_group_right_declined(self):

        models.User_Group_Membership.objects.create(
            creator_id=self.user1.id,
            user_id=self.user1.id,
            group_id=self.group1.id,
            accepted=False
        )

        models.Group_Share_Right.objects.create(
            creator_id=self.user1.id,
            share_id=self.share1.id,
            group_id=self.group1.id,
            read=True,
            write=True,
            grant=True,
        )

        self.assertEqual(
            calculate_user_rights_on_share(self.user1.id, self.share1.id),
            {'read': False, 'grant': False, 'write': False}
        )

    def test_is_allowed_url_successful_with_star(self):
        """
        Tests that '*' in filters allows any domain
        """

        self.assertTrue(is_allowed_url('https://test.me/path/here', ['*']))

    def test_is_allowed_url_successful_with_subpath(self):
        """
        Tests that a subpath is sufficient to allow an url
        """

        self.assertTrue(is_allowed_url('https://test.me/path/here', ['https://test.me/path']))

    def test_is_allowed_url_scheme_downgrades(self):
        """
        Tests that a schema cannot be downgraded http vs https
        """

        self.assertFalse(is_allowed_url('https://test.me/path/here', ['http://test.me/path/here']))

    def test_is_allowed_url_domain_changes(self):
        """
        Tests that a domain change (that wouldn't be detected by a simple prefix check) is actually caught
        """

        self.assertFalse(is_allowed_url('https://test.me.evil.org', ['https://test.me']))

    def test_is_allowed_url_path_traversal(self):
        """
        Tests that a path traversal with .. (that wouldn't be detected by a simple prefix check) is actually caught
        """

        self.assertFalse(is_allowed_url('https://test.me/allowed', ['https://test.me/allowed/../protected']))

    def test_is_allowed_url_path_with_empty_path_in_filter(self):
        """
        Tests that an empty path in is_allowed_url as filter doesn't produce any issues
        """

        self.assertTrue(is_allowed_url('https://test.me/my/path', ['https://test.me']))

    def test_is_allowed_url_path_with_empty_path_in_url(self):
        """
        Tests that an empty path in is_allowed_url in the url doesn't produce any issues
        """

        self.assertTrue(is_allowed_url('https://test.me', ['https://test.me']))

