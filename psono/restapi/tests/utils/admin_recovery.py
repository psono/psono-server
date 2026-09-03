import nacl.encoding
from nacl.public import PrivateKey
from django.test import SimpleTestCase

from restapi.utils import (
    decrypt_with_admin_recovery_private_key,
    encrypt_with_admin_recovery_public_key,
)


class TestAdminRecoveryUtils(SimpleTestCase):
    def test_encrypt_and_decrypt_uses_explicit_private_key(self):
        private_key = PrivateKey.generate()
        public_key_hex = private_key.public_key.encode(
            encoder=nacl.encoding.HexEncoder
        ).decode()
        private_key_hex = private_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        unrelated_private_key_hex = (
            PrivateKey.generate().encode(encoder=nacl.encoding.HexEncoder).decode()
        )

        with self.settings(
            ADMIN_RECOVERY_PUBLIC_KEY=public_key_hex,
            ADMIN_RECOVERY_PRIVATE_KEY=unrelated_private_key_hex,
        ):
            encrypted_text = encrypt_with_admin_recovery_public_key(
                "admin recovery data"
            )
            decrypted_text = decrypt_with_admin_recovery_private_key(
                encrypted_text, private_key_hex
            )

        self.assertNotEqual(encrypted_text, "admin recovery data")
        self.assertEqual(decrypted_text, "admin recovery data")

    def test_encrypt_without_configured_public_key(self):
        with self.settings(ADMIN_RECOVERY_PUBLIC_KEY=""):
            with self.assertRaisesRegex(
                ValueError, "ADMIN_RECOVERY_PUBLIC_KEY is not configured"
            ):
                encrypt_with_admin_recovery_public_key("admin recovery data")
