import nacl.encoding
from nacl.public import Box, PrivateKey
from django.test import SimpleTestCase

from restapi.utils import (
    decrypt_with_admin_recovery_private_key,
    encrypt_with_admin_recovery_public_key,
)


class TestAdminRecoveryUtils(SimpleTestCase):
    def test_encrypt_and_decrypt_uses_explicit_private_key(self):
        admin_private_key = PrivateKey.generate()
        admin_public_key_hex = admin_private_key.public_key.encode(
            encoder=nacl.encoding.HexEncoder
        ).decode()
        admin_private_key_hex = admin_private_key.encode(
            encoder=nacl.encoding.HexEncoder
        ).decode()
        sender_private_key = PrivateKey.generate()
        sender_private_key_hex = sender_private_key.encode(
            encoder=nacl.encoding.HexEncoder
        ).decode()
        sender_public_key_hex = sender_private_key.public_key.encode(
            encoder=nacl.encoding.HexEncoder
        ).decode()
        unrelated_private_key_hex = (
            PrivateKey.generate().encode(encoder=nacl.encoding.HexEncoder).decode()
        )
        plain_text = "a" * 64

        with self.settings(
            ADMIN_RECOVERY_PUBLIC_KEY=admin_public_key_hex,
            ADMIN_RECOVERY_PRIVATE_KEY=unrelated_private_key_hex,
        ):
            encrypted = encrypt_with_admin_recovery_public_key(
                plain_text, sender_private_key_hex
            )
            encrypted_again = encrypt_with_admin_recovery_public_key(
                plain_text, sender_private_key_hex
            )
            decrypted_text = decrypt_with_admin_recovery_private_key(
                encrypted["text"].decode(),
                encrypted["nonce"].decode(),
                sender_public_key_hex,
                admin_private_key_hex,
            )

        self.assertEqual(len(encrypted["text"]), 160)
        self.assertEqual(len(encrypted["nonce"]), 48)
        self.assertNotEqual(encrypted["text"], encrypted_again["text"])
        self.assertNotEqual(encrypted["nonce"], encrypted_again["nonce"])
        self.assertEqual(decrypted_text, plain_text)
        self.assertEqual(
            Box(admin_private_key, sender_private_key.public_key)
            .decrypt(
                nacl.encoding.HexEncoder.decode(encrypted["text"]),
                nacl.encoding.HexEncoder.decode(encrypted["nonce"]),
            )
            .decode(),
            plain_text,
        )

    def test_encrypt_without_configured_public_key(self):
        sender_private_key_hex = (
            PrivateKey.generate().encode(encoder=nacl.encoding.HexEncoder).decode()
        )
        with self.settings(ADMIN_RECOVERY_PUBLIC_KEY=""):
            with self.assertRaisesRegex(
                ValueError, "ADMIN_RECOVERY_PUBLIC_KEY is not configured"
            ):
                encrypt_with_admin_recovery_public_key(
                    "admin recovery data", sender_private_key_hex
                )
