from django.core.management import call_command
from django.test import SimpleTestCase

from contextlib import redirect_stdout
from io import StringIO
import re

import nacl.encoding
from nacl.public import PrivateKey


class CommandGenerateserverkeysTestCase(SimpleTestCase):
    def test_generateserverkeys(self):

        args = []
        opts = {}

        out = StringIO()
        with redirect_stdout(out):
            call_command("generateserverkeys", stdout=out, *args, **opts)

        output = out.getvalue()
        public_key_match = re.search(
            r"ADMIN_RECOVERY_PUBLIC_KEY: '([0-9a-f]{64})'", output
        )
        private_key_match = re.search(
            r"ADMIN_RECOVERY_PRIVATE_KEY: '([0-9a-f]{64})'", output
        )

        self.assertIsNotNone(public_key_match)
        self.assertIsNotNone(private_key_match)
        private_key = PrivateKey(
            private_key_match.group(1), encoder=nacl.encoding.HexEncoder
        )
        self.assertEqual(
            private_key.public_key.encode(encoder=nacl.encoding.HexEncoder).decode(),
            public_key_match.group(1),
        )
        self.assertIn("Print this private key", output)
        self.assertIn("Do NOT copy it into settings.yml", output)
        self.assertLess(
            output.index("ADMIN_RECOVERY_PUBLIC_KEY"),
            output.index("OFFLINE ADMIN RECOVERY PRIVATE KEY"),
        )
