from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("restapi", "0047_user_require_password_change"),
    ]

    operations = [
        migrations.AddField(
            model_name="group_share_right",
            name="expiration_date",
            field=models.DateTimeField(
                blank=True,
                default=None,
                help_text="Defines when this share right expires. Null means permanent.",
                null=True,
                verbose_name="Expiration date",
            ),
        ),
        migrations.AddField(
            model_name="user_share_right",
            name="expiration_date",
            field=models.DateTimeField(
                blank=True,
                default=None,
                help_text="Defines when this share right expires. Null means permanent.",
                null=True,
                verbose_name="Expiration date",
            ),
        ),
    ]
