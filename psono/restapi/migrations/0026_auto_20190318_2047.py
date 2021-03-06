# Generated by Django 2.1.7 on 2019-03-18 20:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('restapi', '0025_auto_20190316_0908'),
    ]

    operations = [
        migrations.AddField(
            model_name='fileserver_cluster_members',
            name='hostname',
            field=models.CharField(default='', max_length=256, verbose_name='Hostname'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='fileserver_cluster_members',
            name='version',
            field=models.CharField(default='', max_length=32, verbose_name='Version'),
            preserve_default=False,
        ),
    ]
