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
                ('nonce', models.CharField(default=b'', max_length=64, verbose_name='nonce')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Data_Store_Owner',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, serialize=False, editable=False, primary_key=True)),
                ('create_date', models.DateTimeField(auto_now_add=True)),
                ('write_date', models.DateTimeField(auto_now=True)),
                ('email', models.EmailField(unique=True, max_length=254, verbose_name='email address')),
                ('authkey', models.CharField(max_length=128, verbose_name='auth key')),
                ('public_key', models.CharField(max_length=256, verbose_name='public key')),
                ('private_key', models.CharField(max_length=256, verbose_name='private key')),
                ('private_key_nonce', models.CharField(max_length=64, verbose_name='private key nonce')),
                ('secret_key', models.CharField(max_length=256, verbose_name='secret key')),
                ('secret_key_nonce', models.CharField(max_length=64, verbose_name='secret key nonce')),
                ('is_email_active', models.BooleanField(default=False, help_text='Designates whether this email should be treated as active. Unselect this if the user registers a new email.', verbose_name='email active')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this owner should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Group',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, serialize=False, editable=False, primary_key=True)),
                ('create_date', models.DateTimeField(auto_now_add=True)),
                ('write_date', models.DateTimeField(auto_now=True)),
                ('owner', models.ForeignKey(related_name='group', to='restapi.Data_Store_Owner')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Group_User_Right',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, serialize=False, editable=False, primary_key=True)),
                ('create_date', models.DateTimeField(auto_now_add=True)),
                ('write_date', models.DateTimeField(auto_now=True)),
                ('read', models.BooleanField(default=True, help_text='Designates whether this user has "read" rights and can read shares of this group', verbose_name='read right')),
                ('write', models.BooleanField(default=False, help_text='Designates whether this user has "write" rights and can update shares of this group', verbose_name='wright right')),
                ('add_share', models.BooleanField(default=False, help_text='Designates whether this user has "add share" rights and can add shares to this group', verbose_name='add share right')),
                ('remove_share', models.BooleanField(default=False, help_text='Designates whether this user has "remove share" rights and can remove shares of this group', verbose_name='remove share right')),
                ('grant', models.BooleanField(default=False, help_text='Designates whether this user has "grant" rights and can add users and rights of users of thisgroup. The user is limited by his own rights, so e.g. he cannot grant write if he does not have write on his own.', verbose_name='grant right')),
                ('revoke', models.BooleanField(default=False, help_text='Designates whether this user has "revoke" rights and can remove users and rights of users of this group. The owner of this group will always have full rights and cannot be shut out.', verbose_name='revoke right')),
                ('group', models.ForeignKey(related_name='group_user_right', to='restapi.Group')),
                ('user', models.ForeignKey(related_name='group_user_right', to='restapi.Data_Store_Owner')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Share',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, serialize=False, editable=False, primary_key=True)),
                ('create_date', models.DateTimeField(auto_now_add=True)),
                ('write_date', models.DateTimeField(auto_now=True)),
                ('data', models.BinaryField()),
                ('type', models.CharField(default=b'password', max_length=64, db_index=True)),
                ('owner', models.ForeignKey(related_name='share', to='restapi.Data_Store_Owner', help_text='The share owner is always the same as the group owner, so the group owner always keeps full control.')),
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
            model_name='group',
            name='shares',
            field=models.ManyToManyField(related_name='groups', to='restapi.Share'),
        ),
        migrations.AddField(
            model_name='data_store',
            name='owner',
            field=models.ForeignKey(related_name='data_store', to='restapi.Data_Store_Owner'),
        ),
    ]
