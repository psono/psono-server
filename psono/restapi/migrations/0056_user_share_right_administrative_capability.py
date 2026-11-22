from django.db import migrations


def add_capability(apps, schema_editor):
    Role = apps.get_model("restapi", "AdministrativeRole")
    Capability = apps.get_model("restapi", "AdministrativeRoleCapability")
    role = Role.objects.filter(system_key="user_administrator").first()
    if role is not None:
        Capability.objects.get_or_create(role=role, capability="users.shares.manage")


def remove_capability(apps, schema_editor):
    Capability = apps.get_model("restapi", "AdministrativeRoleCapability")
    Capability.objects.filter(
        role__system_key="user_administrator", capability="users.shares.manage"
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("restapi", "0055_alter_group_name"),
    ]

    operations = [migrations.RunPython(add_capability, remove_capability)]
