import uuid

from django.db import migrations, models
import django.db.models.deletion


DEFAULT_ROLES = (
    {
        "system_key": "full_administrator",
        "name": "Full Administrator",
        "description": "Access to all administrative capabilities.",
        "is_full_access": True,
        "capabilities": (),
    },
    {
        "system_key": "user_administrator",
        "name": "User Administrator",
        "description": "Manage users and their authentication resources.",
        "is_full_access": False,
        "capabilities": (
            "users.read",
            "users.create",
            "users.update",
            "users.delete",
            "users.sessions.read",
            "users.sessions.delete",
            "users.mfa.delete",
            "users.recovery.read",
            "users.recovery.delete",
            "users.link_shares.delete",
            "security_reports.read",
        ),
    },
    {
        "system_key": "group_administrator",
        "name": "Group Administrator",
        "description": "Manage groups, memberships, and group share rights.",
        "is_full_access": False,
        "capabilities": (
            "groups.read",
            "groups.update",
            "groups.delete",
            "groups.memberships.read",
            "groups.memberships.manage",
            "groups.shares.manage",
        ),
    },
    {
        "system_key": "read_only_auditor",
        "name": "Read-only Auditor",
        "description": "View administrative data without modifying it.",
        "is_full_access": False,
        "capabilities": (
            "system.read",
            "statistics.read",
            "users.read",
            "users.sessions.read",
            "users.recovery.read",
            "security_reports.read",
            "groups.read",
            "groups.memberships.read",
            "fileservers.read",
        ),
    },
    {
        "system_key": "fileserver_administrator",
        "name": "Fileserver Administrator",
        "description": "Manage fileserver infrastructure.",
        "is_full_access": False,
        "capabilities": (
            "fileservers.read",
            "fileservers.manage",
        ),
    },
)


def create_default_roles(apps, schema_editor):
    AdministrativeRole = apps.get_model("restapi", "AdministrativeRole")
    AdministrativeRoleCapability = apps.get_model(
        "restapi", "AdministrativeRoleCapability"
    )

    for definition in DEFAULT_ROLES:
        role = AdministrativeRole.objects.create(
            system_key=definition["system_key"],
            name=definition["name"],
            description=definition["description"],
            is_active=True,
            is_system=True,
            is_full_access=definition["is_full_access"],
        )
        AdministrativeRoleCapability.objects.bulk_create(
            AdministrativeRoleCapability(role=role, capability=capability)
            for capability in definition["capabilities"]
        )


class Migration(migrations.Migration):
    dependencies = [
        ("restapi", "0049_api_key_management_permissions"),
    ]

    operations = [
        migrations.CreateModel(
            name="AdministrativeRole",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("create_date", models.DateTimeField(auto_now_add=True)),
                ("write_date", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=128, unique=True)),
                ("description", models.TextField(blank=True, default="")),
                ("is_active", models.BooleanField(default=True)),
                ("is_system", models.BooleanField(default=False)),
                ("is_full_access", models.BooleanField(default=False)),
                (
                    "system_key",
                    models.CharField(blank=True, max_length=64, null=True, unique=True),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Tenant",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("create_date", models.DateTimeField(auto_now_add=True)),
                ("write_date", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=128, unique=True)),
                ("description", models.TextField(blank=True, default="")),
                ("is_active", models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name="AdministrativeRoleCapability",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("capability", models.CharField(max_length=128)),
                (
                    "role",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="capabilities",
                        to="restapi.administrativerole",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="TenantUserMembership",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("create_date", models.DateTimeField(auto_now_add=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_tenant_user_memberships",
                        to="restapi.user",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="user_memberships",
                        to="restapi.tenant",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tenant_memberships",
                        to="restapi.user",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="TenantGroupMembership",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("create_date", models.DateTimeField(auto_now_add=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_tenant_group_memberships",
                        to="restapi.user",
                    ),
                ),
                (
                    "group",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tenant_memberships",
                        to="restapi.group",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="group_memberships",
                        to="restapi.tenant",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="AdministrativeRoleAssignment",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("create_date", models.DateTimeField(auto_now_add=True)),
                ("write_date", models.DateTimeField(auto_now=True)),
                ("is_global", models.BooleanField(default=False)),
                (
                    "created_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_administrative_role_assignments",
                        to="restapi.user",
                    ),
                ),
                (
                    "role",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="assignments",
                        to="restapi.administrativerole",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="administrative_role_assignments",
                        to="restapi.user",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="AdministrativeRoleAssignmentTenant",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "assignment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tenants",
                        to="restapi.administrativeroleassignment",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="administrative_role_assignments",
                        to="restapi.tenant",
                    ),
                ),
            ],
        ),
        migrations.AddConstraint(
            model_name="administrativerolecapability",
            constraint=models.UniqueConstraint(
                fields=("role", "capability"), name="unique_role_capability"
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantusermembership",
            constraint=models.UniqueConstraint(
                fields=("tenant", "user"), name="unique_tenant_user_membership"
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantgroupmembership",
            constraint=models.UniqueConstraint(
                fields=("tenant", "group"), name="unique_tenant_group_membership"
            ),
        ),
        migrations.AddConstraint(
            model_name="administrativeroleassignment",
            constraint=models.UniqueConstraint(
                fields=("role", "user"),
                name="unique_administrative_role_assignment",
            ),
        ),
        migrations.AddConstraint(
            model_name="administrativeroleassignmenttenant",
            constraint=models.UniqueConstraint(
                fields=("assignment", "tenant"),
                name="unique_administrative_assignment_tenant",
            ),
        ),
        migrations.RunPython(
            create_default_roles,
            migrations.RunPython.noop,
        ),
    ]
