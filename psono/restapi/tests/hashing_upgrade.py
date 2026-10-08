from datetime import timedelta

from django.contrib.auth.hashers import check_password, make_password
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from restapi.models import Old_Credential, Token
from restapi.hashing import is_weaker_hashing_profile
from restapi.utils import create_user, decrypt_secret, encrypt_secret, generate_authkey
import nacl.encoding
import nacl.secret
from .base import APITestCaseExtended


@override_settings(
    PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",),
    DISABLE_LAST_PASSWORDS=5,
)
class HashingUpgradeTests(APITestCaseExtended):
    legacy = {"u": 14, "r": 8, "p": 1, "l": 64}
    stronger = {"u": 15, "r": 8, "p": 1, "l": 64}
    password = "OriginalMasterPassword123!"

    def prepare(self, authentication="AUTHKEY", parameters=None):
        parameters = self.stronger if parameters is None else parameters
        created = create_user(
            f"{authentication.lower()}@psono.pw",
            self.password,
            f"{authentication.lower()}@example.com",
        )
        user = created["user"]
        user.authentication = authentication
        user.require_password_change = True
        user.save()
        tokens = [
            Token.objects.create(
                user=user,
                active=True,
                valid_till=timezone.now() + timedelta(days=1),
            )
            for _ in range(2)
        ]
        self.client.force_authenticate(user=user, token=tokens[0])
        private_key, private_nonce = encrypt_secret(
            created["private_key_decrypted"],
            self.password,
            user.user_sauce.encode(),
            **parameters,
        )
        secret_key, secret_nonce = encrypt_secret(
            created["secret_key_decrypted"],
            self.password,
            user.user_sauce.encode(),
            **parameters,
        )
        payload = {
            "hashing_algorithm": "scrypt",
            "hashing_parameters": parameters,
            "authkey_old": generate_authkey(
                user.username, self.password, **self.legacy
            ).decode(),
            "authkey": generate_authkey(
                user.username, self.password, **parameters
            ).decode(),
            "private_key": private_key.decode(),
            "private_key_nonce": private_nonce.decode(),
            "secret_key": secret_key.decode(),
            "secret_key_nonce": secret_nonce.decode(),
        }
        return user, created, payload

    def test_upgrade_preserves_keys_authentication_sessions_and_password_requirement(
        self,
    ):
        for authentication in ("AUTHKEY", "SAML", "OIDC", "LDAP"):
            with self.subTest(authentication=authentication):
                user, created, payload = self.prepare(authentication)
                Old_Credential.objects.create(
                    user=user,
                    authkey=user.authkey,
                    public_key=user.public_key,
                    private_key=user.private_key,
                    private_key_nonce=user.private_key_nonce,
                    secret_key=user.secret_key,
                    secret_key_nonce=user.secret_key_nonce,
                    hashing_algorithm="scrypt",
                    hashing_parameters=self.legacy,
                )
                response = self.client.put(reverse("user_upgrade_hashing"), payload)
                self.assertEqual(response.status_code, 200, response.data)
                user.refresh_from_db()
                self.assertEqual(user.hashing_parameters, self.stronger)
                self.assertEqual(user.authentication, authentication)
                self.assertTrue(user.require_password_change)
                self.assertTrue(check_password(payload["authkey"], user.authkey))
                self.assertEqual(Token.objects.filter(user=user).count(), 2)
                self.assertFalse(Old_Credential.objects.filter(user=user).exists())
                for field in ("private_key", "secret_key"):
                    self.assertEqual(
                        decrypt_secret(
                            bytes.fromhex(getattr(user, field)),
                            bytes.fromhex(getattr(user, field + "_nonce")),
                            self.password,
                            user.user_sauce.encode(),
                            **self.stronger,
                        ),
                        created[field + "_decrypted"],
                    )
                # Stale requests use the normal old-password validation.
                old_ciphertext = user.private_key
                response = self.client.put(
                    reverse("user_upgrade_hashing"),
                    {
                        **payload,
                        "private_key": "0" * len(payload["private_key"]),
                    },
                )
                self.assertEqual(response.status_code, 400)
                user.refresh_from_db()
                self.assertEqual(user.private_key, old_ciphertext)
                self.assertFalse(Old_Credential.objects.filter(user=user).exists())
                response = self.client.put(
                    reverse("user_upgrade_hashing"),
                    {
                        **payload,
                        "authkey": "0" * 128,
                    },
                )
                self.assertEqual(response.status_code, 400)

    def test_rejects_bad_proof_incomplete_rewrap_and_non_upgrades(self):
        user, _, payload = self.prepare()
        for changes in (
            {"authkey_old": "incorrect"},
            {"secret_key": None},
            {"hashing_parameters": self.legacy},
            {"hashing_parameters": {**self.stronger, "l": 65}},
            {"hashing_parameters": {**self.stronger, "u": 15.0}},
            {"hashing_parameters": {**self.stronger, "r": 8.0}},
            {"hashing_parameters": {**self.stronger, "p": 1.0}},
            {"hashing_parameters": {**self.stronger, "l": 64.0}},
            {"hashing_parameters": {**self.stronger, "p": True}},
            {"hashing_parameters": {**self.stronger, "u": "15"}},
        ):
            with self.subTest(changes=changes):
                response = self.client.put(
                    reverse("user_upgrade_hashing"), {**payload, **changes}
                )
                self.assertEqual(response.status_code, 400)
                user.refresh_from_db()
                self.assertEqual(user.hashing_parameters, self.legacy)

    @override_settings(DISABLE_EMAIL_NEW_LOGIN=True)
    def test_activation_refreshes_credentials_after_a_concurrent_upgrade(self):
        stale_user, _, payload = self.prepare()
        pending_token = Token.objects.create(user=stale_user, active=False)
        response = self.client.put(reverse("user_upgrade_hashing"), payload)
        self.assertEqual(response.status_code, 200)
        self.client.force_authenticate(user=stale_user, token=pending_token)
        box = nacl.secret.SecretBox(
            pending_token.secret_key, encoder=nacl.encoding.HexEncoder
        )
        verification = box.encrypt(pending_token.user_validator.encode())
        response = self.client.post(
            reverse("authentication_activate_token"),
            {
                "verification": verification.ciphertext.hex(),
                "verification_nonce": verification.nonce.hex(),
            },
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["user"]["hashing_parameters"], self.stronger)
        stale_user.refresh_from_db()
        self.assertEqual(stale_user.hashing_parameters, self.stronger)
        self.assertTrue(check_password(payload["authkey"], stale_user.authkey))
        self.assertFalse(Old_Credential.objects.filter(user=stale_user).exists())

    def test_upgrade_replaces_legacy_float_metadata_with_integer_parameters(self):
        user, _, payload = self.prepare()
        user.hashing_parameters = {
            name: float(value) for name, value in self.legacy.items()
        }
        user.save()
        response = self.client.put(reverse("user_upgrade_hashing"), payload)
        self.assertEqual(response.status_code, 200, response.data)
        user.refresh_from_db()
        self.assertEqual(user.hashing_parameters, self.stronger)

    def test_upgrade_accepts_any_stronger_valid_profile(self):
        parameters = {**self.stronger, "u": 16}
        user, _, payload = self.prepare(parameters=parameters)
        original_settings = (user.language, user.user_sauce, user.is_superuser)
        payload.update(
            language="ignored",
            user_sauce="ignored",
            is_superuser=True,
            arbitrary_field={"ignored": True},
        )
        response = self.client.put(reverse("user_upgrade_hashing"), payload)
        self.assertEqual(response.status_code, 200, response.data)
        user.refresh_from_db()
        self.assertEqual(user.hashing_parameters, parameters)
        self.assertEqual(
            (user.language, user.user_sauce, user.is_superuser), original_settings
        )

    def test_upgrade_deletes_only_weaker_history_and_preserves_password_policy(self):
        user, created, payload = self.prepare()
        profiles = (
            self.legacy,
            self.stronger,
            {**self.stronger, "u": 16},
            {**self.legacy, "r": 16},  # Same scrypt costs as the target.
            {**self.legacy, "p": 3},  # Lower memory but higher CPU cost.
        )
        records = []
        for parameters in profiles:
            private_key, private_nonce = encrypt_secret(
                created["private_key_decrypted"],
                self.password,
                user.user_sauce.encode(),
                **parameters,
            )
            secret_key, secret_nonce = encrypt_secret(
                created["secret_key_decrypted"],
                self.password,
                user.user_sauce.encode(),
                **parameters,
            )
            records.append(
                Old_Credential.objects.create(
                    user=user,
                    authkey=make_password(
                        generate_authkey(
                            user.username, self.password, **parameters
                        ).decode()
                    ),
                    public_key=user.public_key,
                    private_key=private_key.decode(),
                    private_key_nonce=private_nonce.decode(),
                    secret_key=secret_key.decode(),
                    secret_key_nonce=secret_nonce.decode(),
                    hashing_algorithm="scrypt",
                    hashing_parameters=parameters,
                )
            )

        # A normal password change still enforces retained password history.
        response = self.client.put(reverse("user_update"), payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn("CANNOT_REUSE_OLD_PASSWORD", response.data["non_field_errors"])
        response = self.client.put(reverse("user_upgrade_hashing"), payload)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(Old_Credential.objects.filter(pk=records[0].pk).exists())
        self.assertSetEqual(
            set(Old_Credential.objects.filter(user=user).values_list("pk", flat=True)),
            {record.pk for record in records[1:]},
        )

    def test_strength_comparison_accounts_for_scrypt_work_factor_tradeoffs(self):
        self.assertTrue(
            is_weaker_hashing_profile(
                "scrypt",
                {"u": 15, "r": 9, "p": 2, "l": 64},
                "scrypt",
                {"u": 17, "r": 8, "p": 1, "l": 64},
            )
        )
        self.assertFalse(
            is_weaker_hashing_profile(
                "scrypt",
                {**self.legacy, "r": 16},
                "scrypt",
                self.stronger,
            )
        )
        self.assertFalse(
            is_weaker_hashing_profile(
                "scrypt",
                {**self.legacy, "p": 3},
                "scrypt",
                self.stronger,
            )
        )
