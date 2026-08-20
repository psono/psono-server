from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("restapi", "0048_share_right_expiration_date"),
    ]

    operations = [
        migrations.AddField(
            model_name="api_key",
            name="allow_admin_access",
            field=models.BooleanField(
                default=False,
                help_text="Allows access to administration API endpoints",
                verbose_name="Allow admin access",
            ),
        ),
        migrations.AddField(
            model_name="api_key",
            name="allow_api_key_management",
            field=models.BooleanField(
                default=False,
                help_text="Allows managing API keys and their secret assignments",
                verbose_name="Allow API key management",
            ),
        ),
    ]
