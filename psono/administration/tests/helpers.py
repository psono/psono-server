import uuid
from datetime import timedelta

from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from restapi import models
from restapi.tests.base import APITestCaseExtended
from restapi.utils import encrypt_with_db_secret


def create_user(name, is_staff=False, is_superuser=False):
    value = uuid.uuid4().hex
    return models.User.objects.create(
        username=f"{name}-{value}@example.com",
        email=encrypt_with_db_secret(f"{name}-{value}@example.com"),
        email_bcrypt=f"hash-{value}",
        authkey="authkey",
        public_key="public-key",
        private_key="private-key",
        private_key_nonce=f"private-{value}",
        secret_key="secret-key",
        secret_key_nonce=f"secret-{value}",
        user_sauce="sauce",
        is_email_active=True,
        is_staff=is_staff,
        is_superuser=is_superuser,
    )


class AdministrativeAccessTestCase(APITestCaseExtended):
    def setUp(self):
        self.superuser = create_user("superuser", True, True)
        self.delegated_admin = create_user("delegated")
        self.staff_without_role = create_user("staff", True)
        self.tenant_a = models.Tenant.objects.create(name="Tenant A")
        self.tenant_b = models.Tenant.objects.create(name="Tenant B")
        self.user_a = create_user("user-a")
        self.user_b = create_user("user-b")
        models.TenantUserMembership.objects.create(
            tenant=self.tenant_a, user=self.user_a, created_by=self.superuser
        )
        models.TenantUserMembership.objects.create(
            tenant=self.tenant_b, user=self.user_b, created_by=self.superuser
        )
        self.role = models.AdministrativeRole.objects.create(name="Tenant User Reader")
        models.AdministrativeRoleCapability.objects.create(
            role=self.role, capability="users.read"
        )
        self.assignment = models.AdministrativeRoleAssignment.objects.create(
            role=self.role, user=self.delegated_admin, is_global=False
        )
        models.AdministrativeRoleAssignmentTenant.objects.create(
            assignment=self.assignment, tenant=self.tenant_a
        )

    def grant(self, capability):
        models.AdministrativeRoleCapability.objects.get_or_create(
            role=self.role, capability=capability
        )

    def create_group(self, name, tenant):
        group = models.Group.objects.create(name=name, public_key="public-key")
        models.TenantGroupMembership.objects.create(
            tenant=tenant, group=group, created_by=self.superuser
        )
        return group

    def assert_tenant_scoped_delete(
        self, url_name, id_field, object_a, object_b, capability
    ):
        model = object_b.__class__
        self.grant(capability)
        self.client.force_authenticate(user=self.delegated_admin)

        response = self.client.delete(reverse(url_name), {id_field: object_a.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.delete(reverse(url_name), {id_field: object_b.id})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(model.objects.filter(pk=object_b.id).exists())


class _FileserverAdministrationTestCase(APITestCaseExtended):
    def setUp(self):
        user_data = {
            "authkey": "authkey",
            "public_key": "public-key",
            "private_key": "private-key",
            "secret_key": "secret-key",
            "user_sauce": "sauce",
            "is_email_active": True,
        }
        self.admin = models.User.objects.create(
            username="fileserver-admin@example.com",
            email=encrypt_with_db_secret("fileserver-admin@example.com"),
            email_bcrypt="admin-email-hash",
            private_key_nonce="private-key-nonce",
            secret_key_nonce="secret-key-nonce",
            is_staff=True,
            **user_data,
        )
        self.user = models.User.objects.create(
            username="fileserver-user@example.com",
            email=encrypt_with_db_secret("fileserver-user@example.com"),
            email_bcrypt="user-email-hash",
            private_key_nonce="private-key-nonce-2",
            secret_key_nonce="secret-key-nonce-2",
            **user_data,
        )
        role = models.AdministrativeRole.objects.create(
            name="Test Fileserver Administrator"
        )
        models.AdministrativeRoleCapability.objects.create(
            role=role, capability="fileservers.read"
        )
        models.AdministrativeRoleCapability.objects.create(
            role=role, capability="fileservers.manage"
        )
        models.AdministrativeRoleAssignment.objects.create(
            role=role, user=self.admin, is_global=True
        )
        self.cluster = models.Fileserver_Cluster.objects.create(
            title="Primary cluster",
            file_size_limit=1024,
            auth_public_key=encrypt_with_db_secret("public-key"),
            auth_private_key=encrypt_with_db_secret("private-key"),
        )
        self.shard = models.Fileserver_Shard.objects.create(
            title="Primary shard", description="Main storage"
        )

    def authenticate(self):
        self.client.force_authenticate(user=self.admin)

    def assert_requires_admin_permissions(self, method, url, data=None):
        request = getattr(self.client, method)

        self.client.force_authenticate(user=None)
        response = request(url, data or {})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        self.client.force_authenticate(user=self.user)
        response = request(url, data or {})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def create_cluster_shard_link(self):
        return models.Fileserver_Cluster_Shard_Link.objects.create(
            cluster=self.cluster,
            shard=self.shard,
        )

    def create_member(self):
        return models.Fileserver_Cluster_Members.objects.create(
            create_ip="127.0.0.1",
            key=f"member-key-{self.cluster.members.count()}",
            fileserver_cluster=self.cluster,
            public_key="member-public-key",
            secret_key="member-secret-key",
            url="https://files.example.com",
            version="1.0.0",
            hostname="files.example.com",
            valid_till=timezone.now() + timedelta(minutes=5),
        )
