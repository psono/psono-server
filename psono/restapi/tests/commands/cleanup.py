from django.core.management import call_command
from django.test import TestCase
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

from restapi import models

import binascii
import random
import string
import os
from io import StringIO

import hashlib

class CommandCleartokenTestCase(TestCase):
    #
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678'
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = 'd22f5797cfd438f212bb0830da488f0555487697ad4041bbcbf5b08bc297e117'
        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data='12345'.encode(),
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data='12345'.encode(),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.secret_link_obj = models.Secret_Link.objects.create(
            link_id = '0493017f-47b0-446e-9a41-6533721ade71',
            secret_id = self.test_secret_obj.id,
            parent_datastore_id = self.test_datastore_obj.id,
            parent_share_id = None
        )


    def test_expired_token(self):

        # Lets put one tokens validity into the future, and one into the past
        self.token = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        models.Token.objects.create(
            key= hashlib.sha512(self.token.encode()).hexdigest(),
            user=self.test_user_obj,
            valid_till=timezone.now() + timedelta(seconds=10)
        )

        self.token2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        models.Token.objects.create(
            key= hashlib.sha512(self.token2.encode()).hexdigest(),
            user=self.test_user_obj,
            valid_till = timezone.now() - timedelta(seconds=10)
        )

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        self.assertEqual(models.Token.objects.count(), 1)

    def test_expired_link_shares(self):
        link_share1 = models.Link_Share.objects.create(
            user=self.test_user_obj,
            secret=self.test_secret_obj,
            file_id=None,
            allowed_reads=True,
            public_title='A public title',
            node=b'kbixmnfhbzmelpujlulqtlulvcvptmauciygeyoipmlehhyuaizhqzzrtjhemdoi',
            node_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            passphrase=None,
            valid_till=timezone.now() + timedelta(seconds=10),
        )

        # The expired link share that should be deleted
        link_share2 = models.Link_Share.objects.create(
            user=self.test_user_obj,
            secret=self.test_secret_obj,
            file_id=None,
            allowed_reads=True,
            public_title='A public title',
            node=b'kbixmnfhbzmelpujlulqtlulvcvptmauciygeyoipmlehhyuaizhqzzrtjhemdoi',
            node_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            passphrase=None,
            valid_till=timezone.now() - timedelta(seconds=10),
        )

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        self.assertEqual(models.Link_Share.objects.count(), 1)
        self.assertTrue(models.Link_Share.objects.filter(pk=link_share1.id).exists())
        self.assertFalse(models.Link_Share.objects.filter(pk=link_share2.id).exists())

    def test_inaccessible_shares(self):
        share_link_id = '1515a857-0bb9-46e0-9a84-97787b3d8ec6'
        test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
            data_nonce="12345",
        )
        test_share1_obj.create_date=timezone.now() - timedelta(days=30)
        test_share1_obj.save()

        models.Share_Tree.objects.create(
            share_id=test_share1_obj.id,
            parent_datastore_id=self.test_datastore_obj.id,
            path=str(share_link_id).replace("-", "")
        )

        # share with missing share tree entry
        test_share2_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
            data_nonce="12345",
        )
        test_share2_obj.create_date=timezone.now() - timedelta(days=30)
        test_share2_obj.save()

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        self.assertEqual(models.Share.objects.count(), 1)
        self.assertTrue(models.Share.objects.filter(pk=test_share1_obj.id).exists())
        self.assertFalse(models.Share.objects.filter(pk=test_share2_obj.id).exists())

    def test_inaccessible_secrets(self):

        inaccessible_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data='12345'.encode(),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        self.assertEqual(models.Secret.objects.count(), 1)
        self.assertTrue(models.Secret.objects.filter(pk=self.test_secret_obj.id).exists())
        self.assertFalse(models.Secret.objects.filter(pk=inaccessible_secret_obj.id).exists())




