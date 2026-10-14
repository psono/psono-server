from datetime import timedelta

from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from restapi import models
from .base import APITestCaseExtended


@override_settings(
    PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
)
class SecurityReportTest(APITestCaseExtended):
    def setUp(self):
        self.user = models.User.objects.create(
            username="reports@example.com",
            email="",
            email_bcrypt="reports",
            authkey=make_password("report-password"),
            private_key_nonce="private",
            secret_key_nonce="secret",
            is_email_active=True,
        )
        self.url = reverse("user_security_report")
        self.client.force_authenticate(user=self.user)

    def test_report_and_entries_are_persisted_with_accurate_counts(self):
        self.user.google_authenticator_enabled = True
        self.user.save(update_fields=["google_authenticator_enabled"])
        models.Recovery_Code.objects.create(user=self.user)
        entries = [
            {
                "type": "website_password",
                "name": "Website",
                "create_age": 3,
                "write_age": 1,
                "master_password": False,
                "duplicate": True,
                "breached": 2,
                "password_length": 8,
                "variation_count": 2,
            },
            {
                "type": "master_password",
                "master_password": True,
                "duplicate": False,
                "breached": 0,
                "password_length": 24,
                "variation_count": 4,
            },
            {"type": "note"},
        ]
        key = "psono_user_status_" + str(self.user.id)
        with override_settings(
            CACHE_ENABLE=True,
            CACHES={
                "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
            },
        ):
            cache.set(key, {"old": "status"})
            self.assertEqual(cache.get(key), {"old": "status"})
            response = self.client.post(
                self.url,
                {
                    "entries": entries,
                    "check_haveibeenpwned": True,
                    "authkey": "report-password",
                },
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertIsNone(cache.get(key))
        report = models.SecurityReport.objects.get(user=self.user)
        self.assertEqual(
            (
                report.website_password_count,
                report.duplicate_password_count,
                report.breached_password_count,
            ),
            (1, 1, 1),
        )
        self.assertTrue(report.recovery_code_exists)
        self.assertTrue(report.two_factor_exists)
        self.assertEqual(report.master_password_length, 24)
        self.assertEqual(report.master_password_variation_count, 4)
        self.assertEqual(report.security_report_entries.count(), 3)
        entry = report.security_report_entries.get(name="Website")
        self.assertEqual(entry.create_age, timedelta(days=3))
        self.assertEqual(entry.write_age, timedelta(days=1))
        self.assertEqual(entry.user, self.user)

    def test_empty_report_is_persisted(self):
        response = self.client.post(
            self.url,
            {
                "entries": [],
                "check_haveibeenpwned": False,
                "authkey": "report-password",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        report = models.SecurityReport.objects.get(user=self.user)
        self.assertFalse(report.recovery_code_exists)
        self.assertFalse(report.two_factor_exists)
        self.assertEqual(report.website_password_count, 0)
        self.assertEqual(report.security_report_entries.count(), 0)

    def test_master_password_entry_can_omit_optional_attributes(self):
        response = self.client.post(
            self.url,
            {
                "entries": [{"type": "master_password", "master_password": True}],
                "check_haveibeenpwned": False,
                "authkey": "report-password",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        report = models.SecurityReport.objects.get(user=self.user)
        self.assertIsNone(report.master_password_length)
        self.assertIsNone(report.master_password_variation_count)
        self.assertEqual(report.security_report_entries.count(), 1)

    def test_invalid_password_creates_no_records(self):
        payload = {
            "entries": [],
            "check_haveibeenpwned": False,
            "authkey": "wrong-password",
        }
        response = self.client.post(self.url, payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("PASSWORD_INCORRECT", response.data["non_field_errors"])
        self.assertFalse(models.SecurityReport.objects.exists())
        self.assertFalse(models.SecurityReportEntry.objects.exists())

    @override_settings(DISABLE_CENTRAL_SECURITY_REPORTS=True)
    def test_disabled_reporting_creates_no_records(self):
        response = self.client.post(
            self.url,
            {
                "entries": [],
                "check_haveibeenpwned": False,
                "authkey": "report-password",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(
            "CENTRAL_SECURITY_REPORTS_DISABLED", response.data["non_field_errors"]
        )
        self.assertFalse(models.SecurityReport.objects.exists())
        self.assertFalse(models.SecurityReportEntry.objects.exists())

    def test_missing_fields_are_rejected(self):
        self.assertEqual(
            self.client.post(self.url, {}).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_metadata_describes_authentication_field(self):
        response = self.client.options(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("authkey", response.data["actions"]["POST"])

    def test_get_is_not_supported(self):
        self.assertEqual(
            self.client.get(self.url).status_code, status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def test_put_is_not_supported(self):
        self.assertEqual(
            self.client.put(self.url, {}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def test_delete_is_not_supported(self):
        self.assertEqual(
            self.client.delete(self.url).status_code, status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def test_authentication_is_required(self):
        self.client.force_authenticate(user=None)
        self.assertEqual(
            self.client.post(self.url, {}).status_code, status.HTTP_401_UNAUTHORIZED
        )
