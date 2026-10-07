import json
from unittest.mock import patch

import nacl.encoding
from nacl.public import Box, PrivateKey, PublicKey
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from restapi.models import Emergency_Code
from restapi.utils import create_user, encrypt_secret, generate_authkey
from .base import APITestCaseExtended


@override_settings(
    PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
)
class EmergencyHashingTests(APITestCaseExtended):
    legacy = {"u": 14, "r": 8, "p": 1, "l": 64}
    account = {"u": 16, "r": 8, "p": 1, "l": 64}
    preferred = {"u": 17, "r": 8, "p": 1, "l": 64}

    @patch(
        "restapi.views.emergency_login.default_hashing_parameters",
        return_value=preferred,
    )
    @patch(
        "restapi.views.emergencycode.default_hashing_parameters", return_value=preferred
    )
    def test_old_and_stronger_code_profiles_unlock_upgraded_accounts(self, *_):
        for code, parameters in (
            ("legacy-emergency-code", self.legacy),
            ("6QZG84jVp2h4qCi6WQmnMBeksqPzA3huq4tUwdSZ7gP8", {**self.legacy, "u": 15}),
        ):
            with self.subTest(parameters=parameters):
                created = create_user(
                    f"code{parameters['u']}@psono.pw",
                    "MasterPassword",
                    f"code{parameters['u']}@example.com",
                )
                user = created["user"]
                for field in ("private_key", "secret_key"):
                    text, nonce = encrypt_secret(
                        created[field + "_decrypted"],
                        "MasterPassword",
                        user.user_sauce.encode(),
                        **self.account,
                    )
                    setattr(user, field, text.decode())
                    setattr(user, field + "_nonce", nonce.decode())
                user.authkey = make_password(
                    generate_authkey(
                        user.username, "MasterPassword", **self.account
                    ).decode()
                )
                user.hashing_parameters = self.account
                user.save()
                self.client.force_authenticate(user=user)
                listing = self.client.get(reverse("emergencycode"))
                self.assertEqual(
                    listing.data["default_hashing_parameters"], self.preferred
                )
                recovered = json.dumps(
                    {
                        "user_private_key": created["private_key_decrypted"].decode(),
                        "user_secret_key": created["secret_key_decrypted"].decode(),
                    }
                ).encode()
                text, nonce = encrypt_secret(
                    recovered, code, b"emergency-sauce", **parameters
                )
                authkey = generate_authkey(user.username, code, **parameters).decode()
                creation = self.client.post(
                    reverse("emergencycode"),
                    {
                        "description": "contact",
                        "activation_delay": 0,
                        "emergency_authkey": authkey,
                        "emergency_data": text.decode(),
                        "emergency_data_nonce": nonce.decode(),
                        "emergency_sauce": "emergency-sauce",
                    },
                )
                self.assertEqual(creation.status_code, 201, creation.data)
                emergency = Emergency_Code.objects.get(
                    pk=creation.data["emergency_code_id"]
                )
                emergency.activation_date = timezone.now()
                emergency.save()
                self.client.force_authenticate(user=None)
                ready = self.client.post(
                    reverse("emergency_login"),
                    {
                        "username": user.username,
                        "emergency_authkey": authkey,
                    },
                )
                self.assertEqual(ready.status_code, 200, ready.data)
                self.assertEqual(ready.data["hashing_parameters"], self.account)
                self.assertEqual(ready.data["user_sauce"], user.user_sauce)
                session = PrivateKey.generate()
                proof = Box(
                    PrivateKey(
                        created["private_key_decrypted"],
                        encoder=nacl.encoding.HexEncoder,
                    ),
                    PublicKey(
                        ready.data["verifier_public_key"],
                        encoder=nacl.encoding.HexEncoder,
                    ),
                ).encrypt(
                    json.dumps(
                        {
                            "session_public_key": session.public_key.encode(
                                nacl.encoding.HexEncoder
                            ).decode()
                        }
                    ).encode()
                )
                response = self.client.put(
                    reverse("emergency_login"),
                    {
                        "username": user.username,
                        "emergency_authkey": authkey,
                        "update_data": proof.ciphertext.hex(),
                        "update_data_nonce": proof.nonce.hex(),
                    },
                )
                self.assertEqual(response.status_code, 200, response.data)
                login = json.loads(
                    Box(
                        session,
                        PublicKey(
                            settings.PUBLIC_KEY, encoder=nacl.encoding.HexEncoder
                        ),
                    ).decrypt(
                        nacl.encoding.HexEncoder.decode(response.data["login_info"]),
                        nacl.encoding.HexEncoder.decode(
                            response.data["login_info_nonce"]
                        ),
                    )
                )
                self.assertEqual(login["hashing_parameters"], self.account)
                self.assertEqual(login["default_hashing_parameters"], self.preferred)
                self.assertNotIn("user_sauce", login)
                user.refresh_from_db()
                self.assertEqual(user.hashing_parameters, self.account)
