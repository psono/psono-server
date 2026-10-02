from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("restapi", "0050_administrative_roles_and_tenants"),
    ]

    operations = [
        migrations.AddField(
            model_name="api_key",
            name="allow_recovery_access",
            field=models.BooleanField(
                default=False,
                help_text="Allows replacing account recovery credentials",
                verbose_name="Allow recovery access",
            ),
        ),
        migrations.AddField(
            model_name="api_key",
            name="allow_emergency_access",
            field=models.BooleanField(
                default=False,
                help_text="Allows managing emergency codes",
                verbose_name="Allow emergency access",
            ),
        ),
    ]
