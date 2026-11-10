from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("restapi", "0054_devicecode_client_type_devicecode_session_duration"),
    ]

    operations = [
        migrations.AlterField(
            model_name="group",
            name="name",
            field=models.CharField(max_length=128),
        ),
    ]
