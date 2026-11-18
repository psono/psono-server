import uuid
from datetime import timedelta

from django.urls import reverse
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase


class UpdateUserShareRightTests(AdministrativeAccessTestCase):
    def setUp(self):
        super().setUp()
        self.url = reverse("admin_user_share_right")
        self.share = models.Share.objects.create(
            user=self.user_b, data=b"encrypted-share", data_nonce="share-nonce"
        )
        self.right = models.User_Share_Right.objects.create(
            user=self.user_a,
            creator=self.user_b,
            share=self.share,
            read=True,
            write=True,
            grant=True,
            accepted=True,
            key="encrypted-key",
            key_nonce="key-nonce",
            title="encrypted-title",
            title_nonce="title-nonce",
            expiration_date=timezone.now() + timedelta(days=1),
        )

    def update(self, user, **changes):
        self.client.force_authenticate(user=user)
        return self.client.put(
            self.url, {"user_share_right_id": self.right.id, **changes}
        )

    def test_superuser_can_change_each_permission_without_share_access(self):
        original = models.User_Share_Right.objects.values().get(pk=self.right.id)
        for permission in ("read", "write", "grant"):
            with self.subTest(permission=permission):
                response = self.update(self.superuser, **{permission: False})
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(response.data, {})
                self.right.refresh_from_db()
                self.assertFalse(getattr(self.right, permission))
                response = self.update(self.superuser, **{permission: True})
                self.assertEqual(response.status_code, status.HTTP_200_OK)
        current = models.User_Share_Right.objects.values().get(pk=self.right.id)
        original.pop("write_date")
        current.pop("write_date")
        self.assertEqual(current, original)
        self.assertFalse(
            models.User_Share_Right.objects.filter(user=self.superuser).exists()
        )

    def test_tenant_scope_is_checked_against_recipient(self):
        self.grant("users.shares.manage")
        response = self.update(
            self.delegated_admin, read=False, write=False, grant=False
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.right.refresh_from_db()
        self.assertFalse(self.right.read)
        self.assertFalse(self.right.write)
        self.assertFalse(self.right.grant)

        self.right.user = self.user_b
        self.right.save()
        response = self.update(self.delegated_admin, read=True)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["non_field_errors"], ["NO_PERMISSION_OR_NOT_EXIST"]
        )
        self.right.refresh_from_db()
        self.assertFalse(self.right.read)

    def test_users_read_does_not_allow_modification(self):
        response = self.update(self.delegated_admin, read=False)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["non_field_errors"], ["ADMIN_PERMISSION_DENIED"])
        self.right.refresh_from_db()
        self.assertTrue(self.right.read)

    def test_delegated_admin_cannot_modify_protected_user(self):
        self.grant("users.shares.manage")
        self.assignment.is_global = True
        self.assignment.save()
        self.right.user = self.superuser
        self.right.save()
        response = self.update(self.delegated_admin, grant=False)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.right.refresh_from_db()
        self.assertTrue(self.right.grant)

    def test_authentication_and_admin_access_required(self):
        for user, expected in (
            (None, status.HTTP_401_UNAUTHORIZED),
            (self.user_a, status.HTTP_403_FORBIDDEN),
            (self.staff_without_role, status.HTTP_403_FORBIDDEN),
        ):
            with self.subTest(user=user):
                response = self.update(user, read=False)
                self.assertEqual(response.status_code, expected)

    def test_invalid_requests_do_not_modify_permissions(self):
        self.client.force_authenticate(user=self.superuser)
        for data in (
            {},
            {"user_share_right_id": "invalid", "read": False},
            {"user_share_right_id": str(uuid.uuid4()), "read": False},
            {"user_share_right_id": self.right.id, "read": "invalid"},
            {"user_share_right_id": self.right.id, "write": None},
        ):
            with self.subTest(data=data):
                response = self.client.put(self.url, data)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.right.refresh_from_db()
        self.assertTrue(self.right.read)
        self.assertTrue(self.right.write)
        self.assertTrue(self.right.grant)

    def test_no_changes_preserves_write_date(self):
        original_write_date = self.right.write_date
        response = self.update(self.superuser)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.right.refresh_from_db()
        self.assertEqual(self.right.write_date, original_write_date)

    def test_other_methods_are_not_supported(self):
        self.client.force_authenticate(user=self.superuser)
        for method in ("get", "post", "patch"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(self.url)
                self.assertEqual(
                    response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED
                )

    def test_user_details_only_expose_share_identifiers_and_permissions(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(
            reverse("admin_user", kwargs={"user_id": self.user_a.id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["share_rights"],
            [
                {
                    "id": self.right.id,
                    "share_id": self.share.id,
                    "create_date": self.right.create_date,
                    "read": True,
                    "write": True,
                    "grant": True,
                    "accepted": True,
                }
            ],
        )

    def test_delete_preserves_share_and_other_permissions(self):
        other_right = models.User_Share_Right.objects.create(
            share=self.share, user=self.user_b, read=True, accepted=True
        )
        group_right = models.Group_Share_Right.objects.create(
            share=self.share,
            group=self.create_group("Shared group", self.tenant_a),
            read=True,
        )
        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(self.url, {"user_share_right_id": self.right.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {})
        self.assertFalse(
            models.User_Share_Right.objects.filter(pk=self.right.id).exists()
        )
        self.assertTrue(
            models.User_Share_Right.objects.filter(pk=other_right.id).exists()
        )
        self.assertTrue(
            models.Group_Share_Right.objects.filter(pk=group_right.id).exists()
        )
        self.share.refresh_from_db()
        self.assertEqual(bytes(self.share.data), b"encrypted-share")

    def test_delete_respects_recipient_tenant_scope(self):
        other_right = models.User_Share_Right.objects.create(
            share=self.share, user=self.user_b
        )
        self.assert_tenant_scoped_delete(
            "admin_user_share_right",
            "user_share_right_id",
            self.right,
            other_right,
            "users.shares.manage",
        )

    def test_delete_requires_authentication_and_manage_capability(self):
        for user, expected in (
            (None, status.HTTP_401_UNAUTHORIZED),
            (self.user_a, status.HTTP_403_FORBIDDEN),
            (self.staff_without_role, status.HTTP_403_FORBIDDEN),
            (self.delegated_admin, status.HTTP_400_BAD_REQUEST),
        ):
            with self.subTest(user=user):
                self.client.force_authenticate(user=user)
                response = self.client.delete(
                    self.url, {"user_share_right_id": self.right.id}
                )
                self.assertEqual(response.status_code, expected)
                self.assertTrue(
                    models.User_Share_Right.objects.filter(pk=self.right.id).exists()
                )

    def test_delete_rejects_protected_users(self):
        self.grant("users.shares.manage")
        self.assignment.is_global = True
        self.assignment.save()
        self.client.force_authenticate(user=self.delegated_admin)
        for user in (self.superuser, self.delegated_admin):
            with self.subTest(user=user):
                self.right.user = user
                self.right.save()
                response = self.client.delete(
                    self.url, {"user_share_right_id": self.right.id}
                )
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertTrue(
                    models.User_Share_Right.objects.filter(pk=self.right.id).exists()
                )

    def test_delete_invalid_or_missing_id(self):
        self.client.force_authenticate(user=self.superuser)
        for data in (
            {},
            {"user_share_right_id": "invalid"},
            {"user_share_right_id": str(uuid.uuid4())},
        ):
            with self.subTest(data=data):
                response = self.client.delete(self.url, data)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(
            models.User_Share_Right.objects.filter(pk=self.right.id).exists()
        )

    @override_settings(
        CACHE_ENABLE=True,
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        },
    )
    def test_delete_expired_pending_right_invalidates_recipient_status(self):
        self.right.accepted = None
        self.right.expiration_date = timezone.now() - timedelta(days=1)
        self.right.save()
        recipient_key = "psono_user_status_" + str(self.user_a.id)
        creator_key = "psono_user_status_" + str(self.user_b.id)
        cache.set(recipient_key, {"cached": True})
        cache.set(creator_key, {"cached": True})
        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(self.url, {"user_share_right_id": self.right.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(
            models.User_Share_Right.objects.filter(pk=self.right.id).exists()
        )
        self.assertIsNone(cache.get(recipient_key))
        self.assertEqual(cache.get(creator_key), {"cached": True})
        cache.delete(creator_key)
