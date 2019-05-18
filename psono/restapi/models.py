from django.db.models.signals import post_save, post_init, post_delete
from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _
from django.dispatch import receiver
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone

from decimal import Decimal
import binascii
import os
from hashlib import sha512
import uuid
from .fields import LtreeField
import nacl.secret
import nacl.utils


class User(models.Model):
    """
    The custom user who owns the data storage
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    username = models.EmailField(_('Username'), unique=True)
    email = models.CharField(_('email address'), max_length=512)
    email_bcrypt = models.CharField(_('bcrypt of email address'), db_index=True, max_length=60)
    authkey = models.CharField(_('auth key'), max_length=128, null=True)
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
    is_superuser = models.BooleanField(_('Admin User'), default=False,
        help_text=_('Designates whether this user is an admin or not.'))
    is_staff = models.BooleanField(_('Has managemnet capabilities'), default=False,
        help_text=_('Designates whether this user has management capabilities or not.'))

    authentication = models.CharField(_('Authentication method'), max_length=16, default='AUTHKEY')
    duo_enabled = models.BooleanField(_('Duo 2FA enabled'), default=False,
        help_text=_('True once duo 2fa is enabled'))
    google_authenticator_enabled = models.BooleanField(_('GA 2FA enabled'), default=False,
        help_text=_('True once ga 2fa is enabled'))
    yubikey_otp_enabled = models.BooleanField(_('Yubikey OTP 2FA enabled'), default=False,
        help_text=_('True once yubikey 2fa is enabled'))

    credit = models.DecimalField(max_digits=24, decimal_places=16, default=Decimal(str(0)))

    is_cachable = True

    def save(self, *args, **kwargs):

        try:
            stored_user = User.objects.get(pk=self.id)

            authkey_changed = self.authkey != stored_user.authkey
            public_key_changed = self.public_key != stored_user.public_key
            secret_key_changed = self.secret_key != stored_user.secret_key
            secret_key_nonce_changed = self.secret_key_nonce != stored_user.secret_key_nonce
            private_key_changed = self.private_key != stored_user.private_key
            private_key_nonce_changed = self.private_key_nonce != stored_user.private_key_nonce
            email_changed = self.email != stored_user.email
            email_bcrypt_changed = self.email_bcrypt != stored_user.email_bcrypt

            if authkey_changed or public_key_changed  or secret_key_changed  or secret_key_nonce_changed  or private_key_changed  or private_key_nonce_changed :
                Old_Credential.objects.create(
                    user_id=stored_user.id,
                    authkey=stored_user.authkey,
                    public_key=stored_user.public_key,
                    secret_key=stored_user.secret_key,
                    secret_key_nonce=stored_user.secret_key_nonce,
                    private_key=stored_user.private_key,
                    private_key_nonce=stored_user.private_key_nonce,
                )

            if email_changed or email_bcrypt_changed :
                Old_Email.objects.create(
                    user_id=stored_user.id,
                    email=stored_user.email,
                    email_bcrypt=stored_user.email_bcrypt,
                )

            if self.is_active:
                for token in self.auth_tokens.all():
                    token.delete()

        except User.DoesNotExist:
            pass

        super(User, self).save(*args, **kwargs)

    class Meta:
        abstract = False

    def get_cache_time(self):
        return settings.DEFAULT_TOKEN_TIME_VALID

    def any_2fa_active(self):
        return self.yubikey_otp_enabled or self.google_authenticator_enabled or self.duo_enabled

    @staticmethod
    def is_authenticated():
        """
        Always return True. This is a way to tell if the user has been
        authenticated.
        """
        return True


class Old_Credential(models.Model):
    """
    Old Credentials
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='old_credentials')
    authkey = models.CharField(_('auth key'), max_length=128, null=True)
    public_key = models.CharField(_('public key'), max_length=256)
    private_key = models.CharField(_('private key'), max_length=256)
    private_key_nonce = models.CharField(_('private key nonce'), max_length=64, unique=True)
    secret_key = models.CharField(_('secret key'), max_length=256)
    secret_key_nonce = models.CharField(_('secret key nonce'), max_length=64, unique=True)

    class Meta:
        abstract = False


class Old_Email(models.Model):
    """
    Old Emails
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='old_emails')
    email = models.CharField(_('email address'), max_length=512, unique=True)
    email_bcrypt = models.CharField(_('bcrypt of email address'), max_length=60)

    class Meta:
        abstract = False


class API_Key(models.Model):
    """
    The API Keys
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    title = models.CharField(_('title'), max_length=256)

    public_key = models.CharField(_('public key'), max_length=256)
    private_key = models.CharField(_('private key'), max_length=256)
    private_key_nonce = models.CharField(_('private key nonce'), max_length=64, unique=True)
    secret_key = models.CharField(_('secret key'), max_length=256)
    secret_key_nonce = models.CharField(_('secret key nonce'), max_length=64, unique=True)

    user_private_key = models.CharField(_('user private key'), max_length=256)
    user_private_key_nonce = models.CharField(_('user private key nonce'), max_length=64, unique=True)
    user_secret_key = models.CharField(_('user secret key'), max_length=256)
    user_secret_key_nonce = models.CharField(_('user secret key nonce'), max_length=64, unique=True)

    verify_key = models.CharField(_('verify key'), max_length=64)

    read = models.BooleanField(_('Read right'), default=True,
                               help_text=_('Allows reading'))
    write = models.BooleanField(_('Write right'), default=False,
                                help_text=_('Allows writing / updating'))

    restrict_to_secrets = models.BooleanField(_('Restrict to specific secrets'), default=False,
                                              help_text=_('Allows access to only spcific secrets'))
    allow_insecure_access = models.BooleanField(_('Allow Insecure Access'), default=False,
                                               help_text=_('Allows API access insecurely without transport encryption or even server side decryption'))
    active = models.BooleanField(_('Is Active?'), default=True,
                                 help_text=_('Designates whether this API key is active or not.'))

    is_cachable = True

    def get_cache_time(self):
        return settings.DEFAULT_TOKEN_TIME_VALID

    class Meta:
        abstract = False


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
    active = models.BooleanField(_('Is Active?'), default=True,
        help_text=_('Designates whether this 2FA is active or not.'))

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
    active = models.BooleanField(_('Is Active?'), default=True,
        help_text=_('Designates whether this 2FA is active or not.'))

    class Meta:
        abstract = False


class Duo(models.Model):
    """
    The Duo model
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='duo')
    title = models.CharField(_('title'), max_length=256)
    duo_integration_key = models.CharField(_('Duo Integration Key'), max_length=32)
    duo_secret_key = models.CharField(_('Encrypted Duo Secret Key'), max_length=256)
    duo_host = models.CharField(_('Duo Host'), max_length=32)
    enrollment_user_id = models.CharField(_('Duo user_id'), max_length=32)
    enrollment_expiration_date = models.DateTimeField(null=True, blank=True)
    enrollment_activation_code = models.CharField(_('Duo Host'), max_length=128)
    active = models.BooleanField(_('Is Active?'), default=True,
        help_text=_('Designates whether this 2FA is active or not.'))

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


class Emergency_Code(models.Model):
    """
    The emergency codes for the lost password recovery process.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='emergency_code')
    emergency_authkey = models.CharField(_('emergency auth key'), max_length=128)
    emergency_data = models.BinaryField()
    emergency_data_nonce = models.CharField(_('emergency data nonce'), max_length=64, unique=True)
    verifier = models.CharField(_('last verifier'), max_length=256)
    verifier_issue_date = models.DateTimeField(null=True, blank=True)
    emergency_sauce = models.CharField(_('user sauce'), max_length=64)

    description = models.CharField(max_length=256, null=True)

    activation_delay = models.PositiveIntegerField(_('Delay till activation in seconds'))
    activation_date = models.DateTimeField(_('Date this emergency code becomes active'), null=True, blank=True)

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
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='secrets')
    data = models.BinaryField()
    data_nonce = models.CharField(_('data nonce'), max_length=64, unique=True)
    type = models.CharField(max_length=64, db_index=True, default='password')
    callback_url = models.CharField(_('Callback URL'), max_length=2048, default='')
    callback_user = models.CharField(_('Callback User'), max_length=128, default='')
    callback_pass = models.CharField(_('Callback Password'), max_length=256, default='')

    class Meta:
        abstract = False


class API_Key_Secret(models.Model):
    """
    The API Key Secrets
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    api_key = models.ForeignKey(API_Key, on_delete=models.CASCADE, related_name='api_key_secrets')
    secret = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name='api_key_secrets')
    secret_key = models.CharField(_('secret key'), max_length=256)
    secret_key_nonce = models.CharField(_('secret key nonce'), max_length=64)
    title = models.CharField(_('title'), max_length=256)
    title_nonce = models.CharField(_('title nonce'), max_length=64)

    class Meta:
        abstract = False
        unique_together = ('api_key', 'secret',)



class Secret_History(models.Model):
    """
    The copy of a secret that is created every time a secret is updated.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='secret_history')
    secret = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name='history')
    data = models.BinaryField()
    data_nonce = models.CharField(_('data nonce'), max_length=64, unique=True)
    type = models.CharField(max_length=64, db_index=True, default='password')
    callback_url = models.CharField(_('Callback URL'), max_length=2048, default='')
    callback_user = models.CharField(_('Callback User'), max_length=128, default='')
    callback_pass = models.CharField(_('Callback Password'), max_length=128, default='')

    class Meta:
        abstract = False


class Share(models.Model):
    """
    The share objects for shares between users. All data encoded.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='shares', null=True,
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
    public_key = models.CharField(_('public key'), max_length=256)


    class Meta:
        abstract = False


class Secret_Link(models.Model):
    """
    The link object for secrets, identifying the position of the secret in a share or datastore
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    secret = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name='links',
                              help_text=_('The secret, that this link links to.'))
    link_id = models.UUIDField(unique=True)
    parent_share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='parent_links', null=True,
                              help_text=_('The share, where this link ends and gets its permissions from'))

    parent_datastore = models.ForeignKey(Data_Store, on_delete=models.CASCADE, related_name='parent_links', null=True,
                                         help_text=_('The datastore, where this link ends'))

    class Meta:
        abstract = False


class Group_Share_Right(models.Model):
    """
    The group-share relation (in contrast to user shares), linking the group and shares with rights

    It contains the encrypted secret of the share (symmetrically encrypted with the group secret)
    together with the rights and other "public" information of the share, like the title.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='group_share_rights',
                              help_text=_('The group who will receive this share right'))
    creator = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='own_group_share_rights',
                              help_text=_('The user who created this share right'), null=True)
    key = models.CharField(_('Key'), max_length=256,
                           help_text=_('The (public or secret) encrypted key with which the share is encrypted.'))
    key_nonce = models.CharField(_('Key nonce'), max_length=64)
    title = models.CharField(_('Title'), max_length=512,
                             help_text=_('The public (yet encrypted) title of the share right.'),
                             null=True)
    title_nonce = models.CharField(_('Title nonce'), max_length=64, null=True)
    type = models.CharField(_('Type'), max_length=512,
                             help_text=_('The public (yet encrypted) type of the share right.'),
                             null=True)
    type_nonce = models.CharField(_('Type nonce'), max_length=64, null=True)
    share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='group_share_rights',
                              help_text=_('The share that this share right grants permissions to'))
    read = models.BooleanField(_('Read right'), default=True,
        help_text=_('Designates whether this user has "read" rights and can read this share'))
    write = models.BooleanField(_('Write right'), default=False,
        help_text=_('Designates whether this user has "write" rights and can update this share'))
    grant = models.BooleanField(_('Grant right'), default=False,
        help_text=_('Designates whether this user has "grant" rights and can re-share this share'))
    # accepted = models.NullBooleanField(_('Accepted'), null=True, blank=True, default=None,
    #     help_text=_('Defines if the share has been accepted, declined, or still waits for approval'))

    class Meta:
        abstract = False
        unique_together = ('group', 'share')


class User_Group_Membership(models.Model):
    """
    The membership management objection, with the relationship between user and group
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_memberships',
                             help_text=_('The user who will receive this share right'))
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='members')
    creator = models.ForeignKey(User, on_delete=models.SET_NULL,
                                help_text=_('The user who created this share right'), null=True)
    secret_key = models.CharField(_('Secret Key'), max_length=256,
                                  help_text=_('The secret key encrypted with the (public or secret) key of the user.'))
    secret_key_nonce = models.CharField(_('Key nonce'), max_length=64)
    secret_key_type = models.CharField(_('Key type'), default="asymmetric",
                                       help_text=_('Key type of the secret key, either "symmetric", or "asymmetric"'),
                                       max_length=16)
    private_key = models.CharField(_('Private key'), max_length=256,
                                   help_text=_('The Private Key encrypted with the (public or secret) key of the user.'))
    private_key_nonce = models.CharField(_('Private Key nonce'), max_length=64)
    private_key_type = models.CharField(_('Private Key type'), default="asymmetric",
                                        help_text=_('Key type of the private key, either "symmetric", or "asymmetric"'),
                                        max_length=16)
    group_admin = models.BooleanField(_('Group admin'), default=False,
                                      help_text=_('Designates whether this user can invite other users to this group, and adjust other user rights.'))
    share_admin = models.BooleanField(_('Share admin'), default=True,
                                      help_text=_('Designates whether this user can add or remove shares from this group.'))
    accepted = models.NullBooleanField(_('Accepted'), null=True, blank=True, default=None,
                                       help_text=_('Defines if the share has been accepted, declined, or still waits for approval'))

    class Meta:
        abstract = False
        unique_together = ('user', 'group',)


class User_Share_Right(models.Model):
    """
    The user-share relation (in contrast to group shares), linking the user and shares with rights

    It is the request that is sent to the user to accept / refuse the share. It contains the encrypted secret of the share
    together with the rights and other "public" information of the share, like the title.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='foreign_user_share_rights',
                              help_text=_('The user who will receive this share right'))
    creator = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='own_user_share_rights',
                              help_text=_('The user who created this share right'), null=True)
    key = models.CharField(_('Key'), max_length=256,
                           help_text=_('The (public or secret) encrypted key with which the share is encrypted.'))
    key_nonce = models.CharField(_('Key nonce'), max_length=64)
    key_type = models.CharField(_('Key type'), default="asymmetric",
                                help_text=_('Key type, either "symmetric", or "asymmetric"'), max_length=16)
    title = models.CharField(_('Title'), max_length=512,
                             help_text=_('The public (yet encrypted) title of the share right.'),
                             null=True)
    title_nonce = models.CharField(_('Title nonce'), max_length=64, null=True)
    type = models.CharField(_('Type'), max_length=512,
                             help_text=_('The public (yet encrypted) type of the share right.'),
                             null=True)
    type_nonce = models.CharField(_('Type nonce'), max_length=64, null=True)
    share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='user_share_rights',
                              help_text=_('The share that this share right grants permissions to'))
    read = models.BooleanField(_('Read right'), default=True,
        help_text=_('Designates whether this user has "read" rights and can read this share'))
    write = models.BooleanField(_('Write right'), default=False,
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


class Fileserver_Cluster(models.Model):
    """
    The Fileserver cluster. A group of fileservers belonging to the same security zone. e.g. "internal vs external" or
    "Core vs DMZ" or "Local vs Cloud" or "HR vs Management vs Rest" or "Document class 1 vs Document class 2"
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    title = models.CharField(_('Title'), max_length=256)
    file_size_limit = models.BigIntegerField('File size limit',
        help_text=_('File size limit in bytes'))
    auth_public_key = models.CharField(_('public key'), max_length=256,
        help_text=_('Public key given to fileservers of this cluster to authenticate against the server'))
    auth_private_key = models.CharField(_('private key'), max_length=256,
        help_text=_('Private key used to validate the request of the '))

    class Meta:
        abstract = False


class Fileserver_Shard(models.Model):
    """
    The shards. Container for files.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    title = models.CharField(_('Title'), max_length=256)
    description = models.TextField(_('Description'))

    active = models.BooleanField(_('Activated'), default=True,
        help_text=_('Specifies if the shard is offline or online'))

    class Meta:
        abstract = False


class Fileserver_Cluster_Shard_Link(models.Model):
    """
    The restrictive rule to allow or block access to shards for members of a cluster
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    cluster = models.ForeignKey(Fileserver_Cluster, on_delete=models.CASCADE, related_name='links',
                              help_text=_('The cluster this shard belongs to'))
    shard = models.ForeignKey(Fileserver_Shard, on_delete=models.CASCADE, related_name='links',
                              help_text=_('The shard this cluster belongs to'))
    read = models.BooleanField(_('Read'), default=True,
        help_text=_('Weather this shard accepts reads'))
    write = models.BooleanField(_('Write'), default=True,
        help_text=_('Weather this shard accepts writes'))
    delete_capability = models.BooleanField(_('Delete'), default=True,
        help_text=_('Weather this connection accepts deletes'))

    class Meta:
        abstract = False
        unique_together = ('cluster', 'shard',)


class Fileserver_Cluster_Members(models.Model):
    """
    The actual members of a fileserver cluster, populated automatically with the current fileservers and their session infos
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)

    create_ip = models.GenericIPAddressField()

    key = models.CharField(max_length=128, unique=True)

    fileserver_cluster = models.ForeignKey(Fileserver_Cluster, on_delete=models.CASCADE, related_name='members',
                              help_text=_('The cluster this member belongs to'))
    public_key = models.CharField(_('public key'), max_length=256,
        help_text=_('Public key of the member that is sent to the client'))
    secret_key = models.CharField(_('Secret Key'), max_length=256,
        help_text=_('Symmetric Key for the transport encryption'))
    url = models.CharField(_('Public URL'), max_length=256)
    version = models.CharField(_('Version'), max_length=32)
    hostname = models.CharField(_('Hostname'), max_length=256)
    read = models.BooleanField(_('Read'), default=True,
        help_text=_('Weather this server accepts reads'))
    write = models.BooleanField(_('Write'), default=True,
        help_text=_('Weather this server accepts writes'))
    delete_capability = models.BooleanField(_('Delete'), default=True,
        help_text=_('Weather this server accepts deletes'))

    valid_till = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        abstract = False

    @staticmethod
    def is_authenticated():
        """
        Always return True. This is a way to tell if the fileserver has been
        authenticated.
        """
        return True


class File_Repository(models.Model):
    """
    The actual members of a fileserver cluster, populated automatically with the current fileservers and their session infos
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)

    title = models.CharField(_('title'), max_length=256)
    type = models.CharField(max_length=32)

    active = models.BooleanField(_('Activated'), default=False,
        help_text=_('Specifies if the file storage is active or not'))

    data = models.BinaryField()

    class Meta:
        abstract = False


class File_Repository_Right(models.Model):
    """
    The access permissions for file repository config.

    Read: The user can read the config
    Write: The user can write / update the config
    Grant: The user can share the config with other users

    Info: These permissions have nothing to do, if a user can download files from this repository. Download permissions
    are determined if the user has access to a file object according to datastore permissions.

    Info: The sole existence of this object for a user means, that he can upload to this repository.
    (even with read = False, write = false, grant = false, as they have nothing to do with the permission to upload)
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='file_repository_right')
    file_repository = models.ForeignKey(File_Repository, on_delete=models.CASCADE, related_name='file_repository_right')

    read = models.BooleanField(_('Read'), default=True,
        help_text=_('Weather this user can read the configured file repository details'))
    write = models.BooleanField(_('Write'), default=True,
        help_text=_('Weather this user can update the configured file repository'))
    grant = models.BooleanField(_('Grant'), default=True,
        help_text=_('Weather this user can change permissions and delete the configured file repository'))
    accepted = models.BooleanField(_('Accepted'), default=False,
                                   help_text=_('Defines if the file repository has been accepted or still waits for approval'))


    class Meta:
        abstract = False


class Fileserver_Cluster_Member_Shard_Link(models.Model):
    """
    The shards that are announced to be accessible by this Cluster Member
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    member = models.ForeignKey(Fileserver_Cluster_Members, on_delete=models.CASCADE, related_name='member_links',
                              help_text=_('The cluster member this link belongs to'))
    shard = models.ForeignKey(Fileserver_Shard, on_delete=models.CASCADE, related_name='member_links',
                              help_text=_('The shard this link belongs to'))
    read = models.BooleanField(_('Read'), default=True,
        help_text=_('Weather this shard accepts reads'))
    write = models.BooleanField(_('Write'), default=True,
        help_text=_('Weather this shard accepts writes'))
    delete_capability = models.BooleanField(_('Delete'), default=True,
        help_text=_('Weather this shard accepts delete jobs'))
    ip_read_whitelist = models.CharField(_('IP read whitelist'), max_length=2048,
        help_text=_('IP Whitelist for read operations'), null=True)
    ip_write_whitelist = models.CharField(_('IP write whitelist'), max_length=2048,
        help_text=_('IP Whitelist for write operations'), null=True)
    ip_read_blacklist = models.CharField(_('IP read blacklist'), max_length=2048,
        help_text=_('IP Blacklist for read operations'), null=True)
    ip_write_blacklist = models.CharField(_('IP write blacklist'), max_length=2048,
        help_text=_('IP Blacklist for write operations'), null=True)

    class Meta:
        abstract = False
        unique_together = ('member', 'shard',)


class File(models.Model):
    """
    The files object.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='file')
    shard = models.ForeignKey(Fileserver_Shard, on_delete=models.CASCADE, null=True, related_name='file')
    file_repository = models.ForeignKey(File_Repository, on_delete=models.CASCADE, null=True, related_name='file')
    chunk_count = models.IntegerField('Chunk Count',
        help_text=_('The amount of chunks'))
    size = models.BigIntegerField('Size',
        help_text=_('The size of the files in bytes (including encryption overhead)'))

    delete_date = models.DateTimeField(null=True)

    class Meta:
        abstract = False


class File_Link(models.Model):
    """
    The link object for files, identifying the position of the file in a share or datastore
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='links',
                              help_text=_('The file, that this link links to.'))
    link_id = models.UUIDField(unique=True)
    parent_share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='files', null=True,
                              help_text=_('The share, where this link ends and gets its permissions from'))

    parent_datastore = models.ForeignKey(Data_Store, on_delete=models.CASCADE, related_name='files', null=True,
                                         help_text=_('The datastore, where this link ends'))

    class Meta:
        abstract = False


class File_Chunk(models.Model):
    """
    The file chunk object.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='file_chunk')
    hash_checksum = models.CharField(max_length=128, unique=True)
    position = models.IntegerField('Position',
        help_text=_('The position of the chunk in the file'))
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='file_chunk')
    size = models.BigIntegerField('Size',
        help_text=_('The size of the chunk in bytes (including encryption overhead)'))

    class Meta:
        abstract = False
        unique_together = ('position', 'file',)



class File_Transfer(models.Model):
    """
    The files transfer object.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='file_transfer')
    file = models.ForeignKey(File, on_delete=models.SET_NULL, null=True, related_name='file_transfer')
    shard = models.ForeignKey(Fileserver_Shard, on_delete=models.SET_NULL, null=True, related_name='file_transfer')
    file_repository = models.ForeignKey(File_Repository, on_delete=models.SET_NULL, null=True, related_name='file_transfer')
    type = models.CharField(max_length=8, default='download')
    credit = models.DecimalField(max_digits=24, decimal_places=16, default=Decimal(str(0)))

    size = models.BigIntegerField('Size',
                                  help_text=_('The amount in bytes that will be transferred (including encryption overhead)'))

    size_transferred = models.BigIntegerField('Transferred Size',
                                              help_text=_('The amount in bytes that have been transferred (including encryption overhead)'))
    chunk_count = models.IntegerField('Chunk Count',
        help_text=_('The amount of chunks'))
    chunk_count_transferred = models.IntegerField('Chunk Count Transfered',
        help_text=_('The amount of chunks already transfered'))

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
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='auth_tokens')
    api_key = models.ForeignKey(API_Key, on_delete=models.CASCADE, null=True, related_name='tokens')
    read = models.BooleanField(_('Read'), default=True, help_text=_('Read permissions'))
    write = models.BooleanField(_('Write'), default=True, help_text=_('Write permissions'))
    active = models.BooleanField(_('Activated'), default=False,
        help_text=_('Specifies if the token has already been activated'))
    is_emergency_session = models.BooleanField(_('Is an emergency session'), default=False,
        help_text=_('Specifies if the token has been created with an emergency code or not'))
    google_authenticator_2fa = models.BooleanField(_('Google Authenticator Required'), default=False,
        help_text=_('Specifies if Google Authenticator is required or not'))

    yubikey_otp_2fa = models.BooleanField(_('Yubikey Required'), default=False,
        help_text=_('Specifies if Yubikey is required or not'))

    duo_2fa = models.BooleanField(_('Duo Required'), default=False,
        help_text=_('Specifies if Duo is required or not'))

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
        self.key = sha512(self.clear_text_key.encode()).hexdigest()

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

@receiver(post_save, sender=API_Key)
def api_key_post_save_receiver(sender, **kwargs):
    if settings.CACHE_ENABLE:
        pk = str(kwargs['instance'].pk)
        cache.set('psono_api_key_' + pk, kwargs['instance'], kwargs['instance'].get_cache_time())

@receiver(post_delete, sender=API_Key)
def api_key_post_delete_receiver(sender, **kwargs):
    if settings.CACHE_ENABLE:
        pk = str(kwargs['instance'].pk)
        cache.delete('psono_api_key_' + pk)
