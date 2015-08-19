# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('restapi', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='key_storage',
            name='create_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 8, 19, 16, 51, 58, 332179, tzinfo=utc), auto_now_add=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='key_storage',
            name='write_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 8, 19, 16, 52, 5, 387765, tzinfo=utc), auto_now=True),
            preserve_default=False,
        ),
    ]
