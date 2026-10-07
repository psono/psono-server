from django.db import migrations, models
import restapi.models


class Migration(migrations.Migration):
    dependencies = [
        ("restapi", "0051_api_key_recovery_emergency_permissions"),
    ]

    operations = [
        # Restore the models' default callable in migration state only. The
        # legacy backfill in 0032 must not depend on it, and existing credential
        # parameters must not be rewritten when the runtime defaults change.
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="old_credential",
                    name="hashing_parameters",
                    field=models.JSONField(
                        default=restapi.models.default_hashing_parameters,
                        verbose_name="hashing parameters",
                    ),
                ),
                migrations.AlterField(
                    model_name="user",
                    name="hashing_parameters",
                    field=models.JSONField(
                        default=restapi.models.default_hashing_parameters,
                        verbose_name="hashing parameters",
                    ),
                ),
            ],
        ),
    ]
