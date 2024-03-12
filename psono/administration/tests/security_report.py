from django.urls import reverse
from django.conf import settings
from rest_framework import status
from restapi.tests.base import APITestCaseExtended
import random
import string
import binascii
import os
from restapi import models

class ReadSecurityReportTest(APITestCaseExtended):
    """
    Test to read security report ressource
    """
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@example.com'
        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@example.com'
        self.test_email_bcrypt = 'a'
        self.test_email_bcrypt2 = 'b'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@psono.pw'
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '6df1f310730e5464ce23e05fa4eca0de3fe30805fc8cc1d6b37389262e4bd9c3'
        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

        self.admin = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            is_superuser=True
        )

        self.security_report = models.SecurityReport.objects.create(
            user=self.test_user_obj,
            recovery_code_exists=False,
            two_factor_exists=False,
            website_password_count=4,
            breached_password_count=5,
            duplicate_password_count=6,
            check_haveibeenpwned=True,
            master_password_breached=False,
            master_password_duplicate=True,
            master_password_length=15,
            master_password_variation_count=3,
        )

        self.security_report_entry = models.SecurityReportEntry.objects.create(
            security_report=self.security_report,
            user=self.test_user_obj,
            name='asdf',
            type='website_password',
            create_age=None,
            write_age=None,
            master_password=None,
            breached=None,
            duplicate=None,
            password_length=None,
            variation_count=None,
        )
    def test_read_all_security_report_success(self):
        """
        Tests to read all security reports
        """

        url = reverse('admin_security_report')

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['security_reports'], [{
            'breached_password_count': self.security_report.breached_password_count,
            'check_haveibeenpwned': self.security_report.check_haveibeenpwned,
            'create_date': self.security_report.create_date,
            'duplicate_password_count': self.security_report.duplicate_password_count,
            'id': self.security_report.id,
            'master_password_breached': self.security_report.master_password_breached,
            'master_password_duplicate': self.security_report.master_password_duplicate,
            'master_password_length': self.security_report.master_password_length,
            'master_password_variation_count': self.security_report.master_password_variation_count,
            'recovery_code_exists': self.security_report.recovery_code_exists,
            'two_factor_exists': self.security_report.two_factor_exists,
            'username': self.test_user_obj.username,
            'website_password_count': self.security_report.website_password_count,
        }])
        self.assertEqual(response.data['user_count'], 2)
        self.assertEqual(len(response.data['users_missing_reports']), 1)

    def test_read_specific_security_report_success(self):
        """
        Tests to read a specific security reports
        """

        url = reverse('admin_security_report', kwargs={'security_report_id': str(self.security_report.id)})

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data,
            {
                'id': self.security_report.id,
                'create_date': self.security_report.create_date,
                'username': self.security_report.user.username,
                'recovery_code_exists': self.security_report.recovery_code_exists,
                'two_factor_exists': self.security_report.two_factor_exists,
                'website_password_count': self.security_report.website_password_count,
                'breached_password_count': self.security_report.breached_password_count,
                'duplicate_password_count': self.security_report.duplicate_password_count,
                'check_haveibeenpwned': self.security_report.check_haveibeenpwned,
                'master_password_breached': self.security_report.master_password_breached,
                'master_password_duplicate': self.security_report.master_password_duplicate,
                'master_password_length': self.security_report.master_password_length,
                'master_password_variation_count': self.security_report.master_password_variation_count,
                'entries': [{
                    'id': self.security_report_entry.id,
                    'name': self.security_report_entry.name,
                    'type': self.security_report_entry.type,
                    'create_age': None,
                    'write_age': None,
                    'master_password': self.security_report_entry.master_password,
                    'breached': self.security_report_entry.breached,
                    'duplicate': self.security_report_entry.duplicate,
                    'password_length': self.security_report_entry.password_length,
                    'variation_count': self.security_report_entry.variation_count,
                }],
            }
        )

    def test_read_specific_security_report_not_exist(self):
        """
        Tests to read a specific security report that doesn't exist
        """

        url = reverse('admin_security_report', kwargs={'security_report_id': '171c6eb8-78b5-455c-a7ff-9c81c348fa51'})

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


    def test_read_security_report_failure_no_admin(self):
        """
        Tests to read info without admin rights
        """

        url = reverse('admin_security_report')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_read_security_report_failure_no_authorization(self):
        """
        Tests to read info without being logged in
        """

        url = reverse('admin_security_report')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_put(self):
        """
        Tests PUT request on security_report
        """

        url = reverse('admin_security_report')

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_post(self):
        """
        Tests POST request on security_report
        """

        url = reverse('admin_security_report')

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete(self):
        """
        Tests DELETE request on security_report
        """

        url = reverse('admin_security_report')

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

