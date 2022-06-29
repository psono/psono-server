# Generated by Django 3.2.12 on 2022-02-10 21:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('restapi', '0029_auto_20200201_0833'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user_group_membership',
            name='accepted',
            field=models.BooleanField(blank=True, default=None, help_text='Defines if the share has been accepted, declined, or still waits for approval', null=True, verbose_name='Accepted'),
        ),
        migrations.AlterField(
            model_name='user_share_right',
            name='accepted',
            field=models.BooleanField(blank=True, default=None, help_text='Defines if the share has been accepted, declined, or still waits for approval', null=True, verbose_name='Accepted'),
        ),
    ]