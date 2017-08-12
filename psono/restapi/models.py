import binascii
import os
from hashlib import sha512
import uuid
from .fields import LtreeField

from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _
from django.dispatch import receiver
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
import nacl.secret
import nacl.utils

from django.db.models.signals import post_save, post_delete


class User(models.Model):
    """
    The custom user who owns the data storage
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    username = models.EmailField(_('Username'), unique=True)
    email = models.CharField(_('email address'), max_length=512, unique=True)
    email_bcrypt = models.CharField(_('bcrypt of email address'), max_length=60, unique=True)
    authkey = models.CharField(_('auth key'), max_length=128)
    public_key = models.CharField(_('public key'), max_length=256)
    private_key = models.CharField(_('private key'), max_length=256)
    private_key_nonce = models.CharField(_('private key nonce'), max_length=64, unique=True)
    secret_key = models.CharField(_('secret key'), max_length=256)
    secret_key_nonce = models.CharField(_('secret key nonce'), max_length=64, unique=True)
    is_email_active = models.BooleanField(_('email active'), default=False,
        help_text=_('Designates whether this email should be treated as '
                    'active. Unselect this if the user registers a new email.'))

    is_active = models.BooleanField(_('active'), default=True,
        help_text=_('Designates whether this user should be treated as '
                    'active. Unselect this instead of deleting accounts.'))
    user_sauce = models.CharField(_('user sauce'), max_length=64)

    is_cachable = True

    class Meta:
        abstract = False

    def get_cache_time(self):
        return settings.DEFAULT_TOKEN_TIME_VALID

    @staticmethod
    def is_authenticated():
        """
        Always return True. This is a way to tell if the user has been
        authenticated.
        """
        return True


class Google_Authenticator(models.Model):
    """
    The Google authenticator model
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='google_authenticator')
    title = models.CharField(_('title'), max_length=256)
    secret = models.CharField(_('secret as hex'), max_length=256)

    class Meta:
        abstract = False


class Yubikey_OTP(models.Model):
    """
    The Yubikey OTP model
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='yubikey_otp')
    title = models.CharField(_('Title'), max_length=256)
    yubikey_id = models.CharField(_('YubiKey ID'), max_length=128)

    class Meta:
        abstract = False


class Recovery_Code(models.Model):
    """
    The recovery codes for the lost password recovery process.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recovery_code')
    recovery_authkey = models.CharField(_('recovery auth key'), max_length=128)
    recovery_data = models.BinaryField()
    recovery_data_nonce = models.CharField(_('recovery data nonce'), max_length=64, unique=True)
    verifier = models.CharField(_('last verifier'), max_length=256)
    verifier_issue_date = models.DateTimeField(null=True, blank=True)
    recovery_sauce = models.CharField(_('user sauce'), max_length=64)

    class Meta:
        abstract = False


class Data_Store(models.Model):
    """
    The data storage where the folder structure is saved
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='data_stores')
    data = models.BinaryField()
    data_nonce = models.CharField(_('data nonce'), max_length=64)
    type = models.CharField(max_length=64, db_index=True, default='password')
    description = models.CharField(max_length=64, default='default')
    secret_key = models.CharField(_('secret key'), max_length=256)
    secret_key_nonce = models.CharField(_('secret key nonce'), max_length=64)
    is_default = models.BooleanField(_('default'), default=True,
        help_text=_('Designates whether this is the default datastore for this type or not'))

    class Meta:
        abstract = False
        unique_together = ('user', 'type', 'description',)


class Secret(models.Model):
    """
    The secret objects for passwords, secure notes, files, whatsoever. The secret is always encrypted with symmetric
    encryption. The key to decrypt the secret is either stored in the data store, or in the share
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='secrets')
    data = models.BinaryField()
    data_nonce = models.CharField(_('data nonce'), max_length=64, unique=True)
    type = models.CharField(max_length=64, db_index=True, default='password')

    class Meta:
        abstract = False


class Share(models.Model):
    """
    The share objects for shares between users. All data encoded.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shares',
                              help_text=_('The share user is always the same as the group user, so the group '
                                          'user always keeps full control.'))
    data = models.BinaryField()
    data_nonce = models.CharField(_('data nonce'), max_length=64)

    class Meta:
        abstract = False


class Group(models.Model):
    """
    The group object is the grouping object that glues shares and user rights together, the user of the group
    automatically owns all shares. A share can only be shared with a second group, if the group users are identical.
    If a share is shared with another person, a new group is created with the user of the first group. This behaviour
    ensures full control for the group user.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    name = models.CharField(max_length=64)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='groups')
    shares = models.ManyToManyField(Share, related_name='groups')

    class Meta:
        abstract = False


class Secret_Link(models.Model):
    """
    The link object for secrets, identifying the position of the Secret in a share or datastore
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    secret = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name='links',
                              help_text=_('The Secret, that this link links to.'))
    link_id = models.UUIDField(unique=True)
    parent_share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='parent_links', null=True,
                              help_text=_('The share, where this link ends and gets its permissions from'))

    parent_datastore = models.ForeignKey(Data_Store, on_delete=models.CASCADE, related_name='parent_links', null=True,
                                         help_text=_('The datastore, where this link ends'))

    class Meta:
        abstract = False


class Group_User_Right(models.Model):
    """
    The group user rights objects for to define rights for group of users and shares.

        read: Designates whether this user has "read" rights and can read shares of this group
        write: Designates whether this user has "write" rights and can update shares of this group
        add_share: Designates whether this user has "add share" rights and can add shares to this group
        remove_share: Designates whether this user has "remove share" rights and can remove shares of this group
        grant: Designates whether this user has "grant" rights and can add / remove users and rights of users of this
            group. The user is limited by his own rights, so e.g. he cannot grant write if he does not have
            write on his own.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_user_rights')
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='group_user_rights')
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='own_group_shares',
                              help_text=_('The guy who created this share'))
    key = models.CharField(_('Key'), max_length=256,
                           help_text=_('The (public or secret) encrypted key with which the share is encrypted.'))
    key_nonce = models.CharField(_('Key nonce'), max_length=64)

    read = models.BooleanField(_('read right'), default=True,
        help_text=_('Designates whether this user has "read" rights and can read shares of this group'))
    write = models.BooleanField(_('wright right'), default=False,
        help_text=_('Designates whether this user has "write" rights and can update shares of this group'))
    add_share = models.BooleanField(_('add share right'), default=False,
        help_text=_('Designates whether this user has "add share" rights and can add shares to this group'))
    remove_share = models.BooleanField(_('remove share right'), default=False,
        help_text=_('Designates whether this user has "remove share" rights and can remove shares of this group'))
    grant = models.BooleanField(_('grant right'), default=False,
        help_text=_('Designates whether this user has "grant" rights and can add users and rights of users of this'
                    'group. The user is limited by his own rights, so e.g. he cannot grant write if he does not have '
                    'write on his own.'))


    class Meta:
        abstract = False


class User_Share_Right(models.Model):
    """
    The user-share relation (in contrast to group shares), linking the user and shares with rights

    It is the request that is sent to the user to accept / refuse the share. It contains the encoded secret of the share
    together with the rights and other "public" information of the share, like the title.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='own_user_share_rights',
                              help_text=_('The guy who created this share right'))
    title = models.CharField(_('Title'), max_length=512,
                             help_text=_('The public (yet encrypted) title of the share right.'),
                             null=True)
    title_nonce = models.CharField(_('Title nonce'), max_length=64, null=True)
    type = models.CharField(_('Type'), max_length=512,
                             help_text=_('The public (yet encrypted) type of the share right.'),
                             null=True)
    type_nonce = models.CharField(_('Type nonce'), max_length=64, null=True)

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='foreign_user_share_rights',
                              help_text=_('The guy who will receive this share right'))
    share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='user_share_rights',
                              help_text=_('The share that this share right grants permissions to'))
    key = models.CharField(_('Key'), max_length=256,
                           help_text=_('The (public or secret) encrypted key with which the share is encrypted.'))
    key_nonce = models.CharField(_('Key nonce'), max_length=64)
    key_type = models.CharField(_('Key type'), default="asymmetric",
                                help_text=_('Key type, either "symmetric", or "asymmetric"'), max_length=16)
    read = models.BooleanField(_('Read right'), default=True,
        help_text=_('Designates whether this user has "read" rights and can read this share'))
    write = models.BooleanField(_('Wright right'), default=False,
        help_text=_('Designates whether this user has "write" rights and can update this share'))
    grant = models.BooleanField(_('Grant right'), default=False,
        help_text=_('Designates whether this user has "grant" rights and can re-share this share'))
    accepted = models.NullBooleanField(_('Accepted'), null=True, blank=True, default=None,
        help_text=_('Defines if the share has been accepted, declined, or still waits for approval'))

    class Meta:
        abstract = False
        unique_together = ('user', 'share',)


class Share_Tree(models.Model):
    """
    This tree structure links shares to other (parent) shares or datastores

    Multiple parents for one child share can exist, same as multiple children can exist for one parent
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='share_trees',
                              help_text=_('The share that this link grants permissions to'))
    path = LtreeField(unique=True, help_text=_('The ltree path to this share'))
    parent_share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='parent_share_trees', null=True,
                              help_text=_('The share, where this link ends and gets its permissions from'))

    parent_datastore = models.ForeignKey(Data_Store, on_delete=models.CASCADE, related_name='parent_share_trees', null=True,
                              help_text=_('The datastore, where this link ends'))

    class Meta:
        abstract = False


@python_2_unicode_compatible
class Token(models.Model):
    """
    The custom authorization token model.
    """
    id = models.UUIDField(db_index=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    valid_till = models.DateTimeField(default=timezone.now)
    key = models.CharField(max_length=128, primary_key=True)
    secret_key = models.CharField(max_length=64)
    user_validator = models.CharField(max_length=64, null=True)
    device_fingerprint = models.CharField(max_length=128, null=True)
    device_description = models.CharField(max_length=256, null=True)
    user = models.ForeignKey(User, related_name='auth_tokens')
    active = models.BooleanField(_('Activated'), default=False,
        help_text=_('Specifies if the token has already been activated'))
    google_authenticator_2fa = models.BooleanField(_('Google Authenticator Required'), default=False,
        help_text=_('Specifies if Google Authenticator is required or not'))

    yubikey_otp_2fa = models.BooleanField(_('Yubikey Required'), default=False,
        help_text=_('Specifies if Yubikey is required or not'))
    client_date = models.DateTimeField(null=True)

    is_cachable = True

    def get_cache_time(self):
        return (self.valid_till - timezone.now()).total_seconds()

    def save(self, *args, **kwargs):
        if not self.key:
            self._generate()

        return super(Token, self).save(*args, **kwargs)

    def _generate(self):
        # clear_text_key will not be saved in db but set as property so a "one-time-access" is possible while this
        # object instance is still alive
        self.clear_text_key = binascii.hexlify(os.urandom(64)).decode()
        self.key = sha512(self.clear_text_key.encode('utf-8')).hexdigest()

        self.secret_key = nacl.encoding.HexEncoder.encode(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)).decode()
        self.user_validator = nacl.encoding.HexEncoder.encode(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)).decode()

    def __str__(self):
        return self.key

    class Meta:
        abstract = False


@receiver(post_save, sender=Token)
def token_post_save_receiver(sender, **kwargs):
    if settings.CACHE_ENABLE:
        pk = str(kwargs['instance'].pk)
        cache.set('psono_token_' + pk, kwargs['instance'], kwargs['instance'].get_cache_time())

@receiver(post_delete, sender=Token)
def token_post_delete_receiver(sender, **kwargs):
    if settings.CACHE_ENABLE:
        pk = str(kwargs['instance'].pk)
        cache.delete('psono_token_' + pk)

@receiver(post_save, sender=User)
def user_post_save_receiver(sender, **kwargs):
    if settings.CACHE_ENABLE:
        pk = str(kwargs['instance'].pk)
        cache.set('psono_user_' + pk, kwargs['instance'], kwargs['instance'].get_cache_time())

@receiver(post_delete, sender=User)
def user_post_delete_receiver(sender, **kwargs):
    if settings.CACHE_ENABLE:
        pk = str(kwargs['instance'].pk)
        cache.delete('psono_user_' + pk)

