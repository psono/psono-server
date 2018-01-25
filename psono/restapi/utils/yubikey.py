from django.conf import settings
from yubico_client import Yubico


def yubikey_authenticate(yubikey_otp):
    """
    Checks a YubiKey OTP

    :param yubikey_otp: Yubikey OTP
    :type yubikey_otp:
    :return: True or False or None
    :rtype: bool
    """

    if settings.YUBIKEY_CLIENT_ID is None or settings.YUBIKEY_SECRET_KEY is None:
        return None

    client = Yubico(settings.YUBIKEY_CLIENT_ID, settings.YUBIKEY_SECRET_KEY)
    try:
        yubikey_is_valid = client.verify(yubikey_otp)
    except:
        yubikey_is_valid = False

    return yubikey_is_valid


def yubikey_get_yubikey_id(yubikey_otp):
    """
    Returns the yubikey id based

    :param yubikey_otp: Yubikey OTP
    :type yubikey_otp: str
    :return: Yubikey ID
    :rtype: str
    """

    yubikey_otp = str(yubikey_otp).strip()

    return yubikey_otp[:12]