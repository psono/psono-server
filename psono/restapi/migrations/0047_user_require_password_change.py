from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("restapi", "0046_file_secret"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="require_password_change",
            field=models.BooleanField(
                default=False, verbose_name="require password change"
            ),
        ),
    ]
