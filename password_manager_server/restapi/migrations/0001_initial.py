# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import uuid


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Data_Store',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, serialize=False, editable=False, primary_key=True)),
                ('create_date', models.DateTimeField(auto_now_add=True)),
                ('write_date', models.DateTimeField(auto_now=True)),
                ('data', models.BinaryField()),
                ('type', models.CharField(default=b'password', max_length=64, db_index=True)),
                ('description', models.CharField(default=b'default', max_length=64)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Data_Store_Owner',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('create_date', models.DateTimeField(auto_now_add=True)),
                ('write_date', models.DateTimeField(auto_now=True)),
                ('email', models.EmailField(unique=True, max_length=254, verbose_name='email address')),
                ('authkey', models.CharField(max_length=128, verbose_name='auth key')),
                ('is_email_active', models.BooleanField(default=False, help_text='Designates whether this email should be treated as active. Unselect this if the user registers a new email.', verbose_name='email active')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this owner should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Token',
            fields=[
                ('create_date', models.DateTimeField(auto_now_add=True)),
                ('key', models.CharField(max_length=64, serialize=False, primary_key=True)),
                ('owner', models.ForeignKey(related_name='auth_token', to='restapi.Data_Store_Owner')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='data_store',
            name='owner',
            field=models.ForeignKey(related_name='data_store', to='restapi.Data_Store_Owner'),
        ),
    ]
