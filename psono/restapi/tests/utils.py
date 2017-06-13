from base import APITestCaseExtended
from restapi.utils import authenticate, yubikey_authenticate, yubikey_get_yubikey_id
from mock import patch


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


class TestUtils(APITestCaseExtended):
    def test_authenticate_with_no_authkey(self):
        """
        Test authentication without authkey
        """
        self.assertFalse(authenticate('asdf', False, False))

    def test_authenticate_with_no_username_nor_user_object(self):
        """
        Test authentication without username nor user object
        """
        self.assertFalse(authenticate(False, False, 'asdf'))

    def test_authenticate_with_wrong_username(self):
        """
        Test authentication with wrong username
        """
        self.assertFalse(authenticate('narf', False, 'asdf'))

    @patch('restapi.utils.settings', YUBIKEY_CLIENT_ID='123', YUBIKEY_SECRET_KEY='T3VoIHlvdSBmb3VuZCBtZT8=')
    @patch('restapi.utils.Yubico.verify', side_effect=yubico_verify_true)
    def test_yubikey_authenticate_works(self, settings_fct, yubico_verify_true_fct):
        self.assertTrue(yubikey_authenticate(5))

    @patch('restapi.utils.settings', YUBIKEY_CLIENT_ID=None, YUBIKEY_SECRET_KEY='T3VoIHlvdSBmb3VuZCBtZT8=')
    def test_yubikey_authenticate_client_id_none(self, settings_fct):
        self.assertIsNone(yubikey_authenticate(5))

    @patch('restapi.utils.settings', YUBIKEY_CLIENT_ID='123', YUBIKEY_SECRET_KEY=None)
    def test_yubikey_authenticate_secret_key_none(self, settings_fct):
        self.assertIsNone(yubikey_authenticate(5))

    def test_yubikey_authenticate_secret_key_none(self):
        self.assertEqual(yubikey_get_yubikey_id('iuhsrgknjbfjbfdkljbfdjiufiojfd'), 'iuhsrgknjbfj')
