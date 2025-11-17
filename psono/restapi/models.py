from django.db.models.signals import post_save, post_delete, pre_delete
from django.db import models
from django.dispatch import receiver
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from timezone_field import TimeZoneField
from django_countries.fields import CountryField


from decimal import Decimal
import binascii
import os
from hashlib import sha512
import uuid
from .fields import LtreeField
import nacl.secret
import nacl.utils


def default_hashing_parameters():
    return {
        "u": 14,
        "r": 8,
        "p": 1,
        "l": 64
    }


HASHING_ALGORITHM_SCRYPT = 'scrypt'
HASHING_ALGORITHMS = [
    (HASHING_ALGORITHM_SCRYPT, 'scrypt'),
]
DEFAULT_HASHING_ALGORITHM = HASHING_ALGORITHM_SCRYPT


class User(models.Model):
    """
    The custom user who owns the data storage
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    username = models.EmailField('Username', unique=True)
    email = models.CharField('email address', max_length=512)
    email_bcrypt = models.CharField('bcrypt of email address', db_index=True, max_length=60)
    authkey = models.CharField('auth key', max_length=128, null=True)
    public_key = models.CharField('public key', max_length=256)
    private_key = models.CharField('private key', max_length=256)
    private_key_nonce = models.CharField('private key nonce', max_length=64, unique=True)
    secret_key = models.CharField('secret key', max_length=256)
    secret_key_nonce = models.CharField('secret key nonce', max_length=64, unique=True)
    is_email_active = models.BooleanField('email active', default=False,
        help_text='Designates whether this email should be treated as '
                    'active. Unselect this if the user registers a new email.')

    is_active = models.BooleanField('active', default=True,
        help_text='Designates whether this user should be treated as '
                    'active. Unselect this instead of deleting accounts.')
    user_sauce = models.CharField('user sauce', max_length=64)
    is_superuser = models.BooleanField('Admin User', default=False,
        help_text='Designates whether this user is an admin or not.')
    is_staff = models.BooleanField('Has managemnet capabilities', default=False,
        help_text='Designates whether this user has management capabilities or not.')

    authentication = models.CharField('Authentication method', max_length=16, default='AUTHKEY')
    duo_enabled = models.BooleanField('Duo 2FA enabled', default=False,
        help_text='True once duo 2fa is enabled')
    google_authenticator_enabled = models.BooleanField('GA 2FA enabled', default=False,
        help_text='True once ga 2fa is enabled')
    yubikey_otp_enabled = models.BooleanField('Yubikey OTP 2FA enabled', default=False,
        help_text='True once yubikey 2fa is enabled')
    webauthn_enabled = models.BooleanField('Webauthn 2FA enabled', default=False,
        help_text='True once webauthn 2fa is enabled')
    ivalt_enabled = models.BooleanField('iValt 2FA enabled', default=False,
        help_text='True once ivalt 2fa is enabled')
    display_name = models.CharField('display name', max_length=512, default='')
    last_login = models.DateTimeField(default=timezone.now)
    hashing_algorithm = models.CharField('hashing algorithm', max_length=32, default=DEFAULT_HASHING_ALGORITHM, choices=HASHING_ALGORITHMS,)
    hashing_parameters = models.JSONField('hashing parameters', default=default_hashing_parameters)
    zoneinfo = TimeZoneField(null=True)
    country = CountryField(null=True)

    credit = models.DecimalField(max_digits=24, decimal_places=16, default=Decimal(str(0)))

    language = models.CharField('language', max_length=16, default='en')
    external_id = models.CharField('external id', max_length=64, null=True, db_index=True)

    is_cachable = True

    def save(self, *args, **kwargs):

        if self.is_superuser:
            self.is_staff = True

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
            hashing_algorithm_changed = self.hashing_algorithm != stored_user.hashing_algorithm
            hashing_parameters_changed = self.hashing_parameters != stored_user.hashing_parameters

            if authkey_changed or public_key_changed  or secret_key_changed  or secret_key_nonce_changed  or private_key_changed  or private_key_nonce_changed:

                if hashing_parameters_changed or hashing_algorithm_changed:
                    Old_Credential.objects.filter(user_id=stored_user.id).delete()

                Old_Credential.objects.create(
                    user_id=stored_user.id,
                    authkey=stored_user.authkey,
                    public_key=stored_user.public_key,
                    secret_key=stored_user.secret_key,
                    secret_key_nonce=stored_user.secret_key_nonce,
                    private_key=stored_user.private_key,
                    private_key_nonce=stored_user.private_key_nonce,
                    hashing_algorithm=stored_user.hashing_algorithm,
                    hashing_parameters=stored_user.hashing_parameters,
                )

            if email_changed or email_bcrypt_changed :
                Old_Email.objects.create(
                    user_id=stored_user.id,
                    email=stored_user.email,
                    email_bcrypt=stored_user.email_bcrypt,
                )

            if not self.is_active:
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
        return self.yubikey_otp_enabled or self.google_authenticator_enabled or self.duo_enabled or self.webauthn_enabled or self.ivalt_enabled

    @staticmethod
    def is_authenticated():
        """
        Always return True. This is a way to tell if the user has been
        authenticated.
        """
        return True


class Avatar(models.Model):
    """
    Avatar images
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='avatar')
    data = models.BinaryField(null=True)
    mime_type = models.CharField(max_length=255)

    class Meta:
        abstract = False


class Old_Credential(models.Model):
    """
    Old Credentials
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='old_credentials')
    authkey = models.CharField('auth key', max_length=128, null=True)
    public_key = models.CharField('public key', max_length=256)
    private_key = models.CharField('private key', max_length=256)
    private_key_nonce = models.CharField('private key nonce', max_length=64, unique=True)
    secret_key = models.CharField('secret key', max_length=256)
    secret_key_nonce = models.CharField('secret key nonce', max_length=64, unique=True)
    hashing_algorithm = models.CharField('hashing algorithm', max_length=32, default=DEFAULT_HASHING_ALGORITHM, choices=HASHING_ALGORITHMS,)
    hashing_parameters = models.JSONField('hashing parameters', default=default_hashing_parameters)

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
    email = models.CharField('email address', max_length=512, unique=True)
    email_bcrypt = models.CharField('bcrypt of email address', max_length=60)

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
    title = models.CharField('title', max_length=256)

    public_key = models.CharField('public key', max_length=256)
    private_key = models.CharField('private key', max_length=256)
    private_key_nonce = models.CharField('private key nonce', max_length=64, unique=True)
    secret_key = models.CharField('secret key', max_length=256)
    secret_key_nonce = models.CharField('secret key nonce', max_length=64, unique=True)

    user_private_key = models.CharField('user private key', max_length=256)
    user_private_key_nonce = models.CharField('user private key nonce', max_length=64, unique=True)
    user_secret_key = models.CharField('user secret key', max_length=256)
    user_secret_key_nonce = models.CharField('user secret key nonce', max_length=64, unique=True)

    verify_key = models.CharField('verify key', max_length=64)

    read = models.BooleanField('Read right', default=True,
                               help_text='Allows reading')
    write = models.BooleanField('Write right', default=False,
                                help_text='Allows writing / updating')

    restrict_to_secrets = models.BooleanField('Restrict to specific secrets', default=False,
                                              help_text='Allows access to only spcific secrets')
    allow_insecure_access = models.BooleanField('Allow Insecure Access', default=False,
                                               help_text='Allows API access insecurely without transport encryption or even server side decryption')
    active = models.BooleanField('Is Active?', default=True,
                                 help_text='Designates whether this API key is active or not.')

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
    title = models.CharField('title', max_length=256)
    secret = models.CharField('secret as hex', max_length=256)
    active = models.BooleanField('Is Active?', default=True,
        help_text='Designates whether this 2FA is active or not.')

    class Meta:
        abstract = False


class Webauthn(models.Model):
    """
    The Google authenticator model
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn')
    title = models.CharField('title', max_length=256)
    origin = models.CharField('origin', max_length=512)
    rp_id = models.CharField('rp_id', max_length=512)
    credential_id = models.TextField('The credential id as passed from the frontend', default="")
    credential_public_key = models.TextField('The credential public key as passed from the frontend', default="")
    challenge = models.TextField('The challenge encrypted with the db secret')
    active = models.BooleanField('Is Active?', default=True,
        help_text='Designates whether this 2FA is active or not.')

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
    title = models.CharField('Title', max_length=256)
    yubikey_id = models.CharField('YubiKey ID', max_length=128)
    active = models.BooleanField('Is Active?', default=True,
        help_text='Designates whether this 2FA is active or not.')

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
    title = models.CharField('title', max_length=256)
    duo_integration_key = models.CharField('Duo Integration Key', max_length=32)
    duo_secret_key = models.CharField('Encrypted Duo Secret Key', max_length=256)
    duo_host = models.CharField('Duo Host', max_length=32)
    enrollment_user_id = models.CharField('Duo user_id', max_length=32)
    enrollment_expiration_date = models.DateTimeField(null=True, blank=True)
    enrollment_activation_code = models.CharField('Duo Host', max_length=128)
    active = models.BooleanField('Is Active?', default=True,
        help_text='Designates whether this 2FA is active or not.')

    class Meta:
        abstract = False

class Ivalt(models.Model):
    """
    The iValt 2FA model
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ivalt')
    mobile = models.CharField('Mobile', max_length=256)
    active = models.BooleanField('Is Active?', default=True,
                                 help_text='Designates whether this 2FA is active or not.')

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
    recovery_authkey = models.CharField('recovery auth key', max_length=128)
    recovery_data = models.BinaryField()
    recovery_data_nonce = models.CharField('recovery data nonce', max_length=64, unique=True)
    verifier = models.CharField('last verifier', max_length=256)
    verifier_issue_date = models.DateTimeField(null=True, blank=True)
    recovery_sauce = models.CharField('user sauce', max_length=64)

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
    emergency_authkey = models.CharField('emergency auth key', max_length=128)
    emergency_data = models.BinaryField()
    emergency_data_nonce = models.CharField('emergency data nonce', max_length=64, unique=True)
    verifier = models.CharField('last verifier', max_length=256)
    verifier_issue_date = models.DateTimeField(null=True, blank=True)
    emergency_sauce = models.CharField('user sauce', max_length=64)

    description = models.CharField(max_length=256, null=True)

    activation_delay = models.PositiveIntegerField('Delay till activation in seconds')
    activation_date = models.DateTimeField('Date this emergency code becomes active', null=True, blank=True)

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
    data_nonce = models.CharField('data nonce', max_length=64)
    type = models.CharField(max_length=64, db_index=True, default='password')
    description = models.CharField(max_length=64, default='default')
    secret_key = models.CharField('secret key', max_length=256)
    secret_key_nonce = models.CharField('secret key nonce', max_length=64)
    is_default = models.BooleanField('default', default=True,
        help_text='Designates whether this is the default datastore for this type or not')

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
    data_nonce = models.CharField('data nonce', max_length=64, unique=True)
    type = models.CharField(max_length=64, db_index=True, default='password')
    callback_url = models.CharField('Callback URL', max_length=2048, default='')
    callback_user = models.CharField('Callback User', max_length=128, default='')
    callback_pass = models.CharField('Callback Password', max_length=256, default='')
    read_count = models.IntegerField('Read Count',
                                     help_text='A counter how often this secret has been read so far', default=0)

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
    secret_key = models.CharField('secret key', max_length=256)
    secret_key_nonce = models.CharField('secret key nonce', max_length=64)
    title = models.CharField('title', max_length=256)
    title_nonce = models.CharField('title nonce', max_length=64)

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
    data_nonce = models.CharField('data nonce', max_length=64, unique=True)
    type = models.CharField(max_length=64, db_index=True, default='password')
    callback_url = models.CharField('Callback URL', max_length=2048, default='')
    callback_user = models.CharField('Callback User', max_length=128, default='')
    callback_pass = models.CharField('Callback Password', max_length=128, default='')

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
                              help_text='The share user is always the same as the group user, so the group '
                                          'user always keeps full control.')
    data = models.BinaryField()
    data_nonce = models.CharField('data nonce', max_length=64)

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
    public_key = models.CharField('public key', max_length=256)
    forced_membership = models.BooleanField('Forced Membership', default=False,
                                            help_text='Designates whether users can deny or leave this groups membership')
    is_managed = models.BooleanField('Managed', default=False,)


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
                              help_text='The secret, that this link links to.')
    link_id = models.UUIDField(unique=True)
    parent_share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='parent_links', null=True,
                              help_text='The share, where this link ends and gets its permissions from')

    parent_datastore = models.ForeignKey(Data_Store, on_delete=models.CASCADE, related_name='parent_links', null=True,
                                         help_text='The datastore, where this link ends')

    class Meta:
        abstract = False


class Group_Share_Right(models.Model):
    """
    The group-share relation (in contrast to user shares, linking the group and shares with rights

    It contains the encrypted secret of the share (symmetrically encrypted with the group secret)
    together with the rights and other "public" information of the share, like the title.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='group_share_rights',
                              help_text='The group who will receive this share right')
    creator = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='own_group_share_rights',
                              help_text='The user who created this share right', null=True)
    key = models.CharField('Key', max_length=256,
                           help_text='The (public or secret) encrypted key with which the share is encrypted.')
    key_nonce = models.CharField('Key nonce', max_length=64)
    title = models.CharField('Title', max_length=512,
                             help_text='The public (yet encrypted) title of the share right.',
                             null=True)
    title_nonce = models.CharField('Title nonce', max_length=64, null=True)
    type = models.CharField('Type', max_length=512,
                             help_text='The public (yet encrypted) type of the share right.',
                             null=True)
    type_nonce = models.CharField('Type nonce', max_length=64, null=True)
    share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='group_share_rights',
                              help_text='The share that this share right grants permissions to')
    read = models.BooleanField('Read right', default=True,
        help_text='Designates whether this user has "read" rights and can read this share')
    write = models.BooleanField('Write right', default=False,
        help_text='Designates whether this user has "write" rights and can update this share')
    grant = models.BooleanField('Grant right', default=False,
        help_text='Designates whether this user has "grant" rights and can re-share this share')
    # accepted = models.BooleanField('Accepted', null=True, blank=True, default=None,
    #     help_text='Defines if the share has been accepted, declined, or still waits for approval')

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
                             help_text='The user who will receive this share right')
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='members')
    creator = models.ForeignKey(User, on_delete=models.SET_NULL,
                                help_text='The user who created this share right', null=True)
    secret_key = models.CharField('Secret Key', max_length=256,
                                  help_text='The secret key encrypted with the (public or secret) key of the user.', null=True)
    secret_key_nonce = models.CharField('Key nonce', max_length=64, null=True)
    secret_key_type = models.CharField('Key type', default="asymmetric",
                                       help_text='Key type of the secret key, either "symmetric", or "asymmetric"',
                                       max_length=16, null=True)
    private_key = models.CharField('Private key', max_length=256,
                                   help_text='The Private Key encrypted with the (public or secret) key of the user.', null=True)
    private_key_nonce = models.CharField('Private Key nonce', max_length=64, null=True)
    private_key_type = models.CharField('Private Key type', default="asymmetric",
                                        help_text='Key type of the private key, either "symmetric", or "asymmetric"',
                                        max_length=16, null=True)
    group_admin = models.BooleanField('Group admin', default=False,
                                      help_text='Designates whether this user can invite other users to this group, and adjust other user rights.')
    share_admin = models.BooleanField('Share admin', default=True,
                                      help_text='Designates whether this user can add or remove shares from this group.')
    accepted = models.BooleanField('Accepted', null=True, blank=True, default=None,
                                       help_text='Defines if the share has been accepted, declined, or still waits for approval')

    class Meta:
        abstract = False
        unique_together = ('user', 'group',)


class User_Share_Right(models.Model):
    """
    The user-share relation (in contrast to group shares, linking the user and shares with rights

    It is the request that is sent to the user to accept / refuse the share. It contains the encrypted secret of the share
    together with the rights and other "public" information of the share, like the title.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='foreign_user_share_rights',
                              help_text='The user who will receive this share right')
    creator = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='own_user_share_rights',
                              help_text='The user who created this share right', null=True)
    key = models.CharField('Key', max_length=256,
                           help_text='The (public or secret) encrypted key with which the share is encrypted.')
    key_nonce = models.CharField('Key nonce', max_length=64)
    key_type = models.CharField('Key type', default="asymmetric",
                                help_text='Key type, either "symmetric", or "asymmetric"', max_length=16)
    title = models.CharField('Title', max_length=512,
                             help_text='The public (yet encrypted) title of the share right.',
                             null=True)
    title_nonce = models.CharField('Title nonce', max_length=64, null=True)
    type = models.CharField('Type', max_length=512,
                             help_text='The public (yet encrypted) type of the share right.',
                             null=True)
    type_nonce = models.CharField('Type nonce', max_length=64, null=True)
    share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='user_share_rights',
                              help_text='The share that this share right grants permissions to')
    read = models.BooleanField('Read right', default=True,
        help_text='Designates whether this user has "read" rights and can read this share')
    write = models.BooleanField('Write right', default=False,
        help_text='Designates whether this user has "write" rights and can update this share')
    grant = models.BooleanField('Grant right', default=False,
        help_text='Designates whether this user has "grant" rights and can re-share this share')
    accepted = models.BooleanField('Accepted', null=True, blank=True, default=None,
        help_text='Defines if the share has been accepted, declined, or still waits for approval')

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
                              help_text='The share that this link grants permissions to')
    path = LtreeField(unique=True, help_text='The ltree path to this share')
    parent_share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='parent_share_trees', null=True,
                              help_text='The share, where this link ends and gets its permissions from')

    parent_datastore = models.ForeignKey(Data_Store, on_delete=models.CASCADE, related_name='parent_share_trees', null=True,
                              help_text='The datastore, where this link ends')

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
    title = models.CharField('Title', max_length=256)
    file_size_limit = models.BigIntegerField('File size limit',
        help_text='File size limit in bytes')
    auth_public_key = models.CharField('public key', max_length=256,
        help_text='Public key given to fileservers of this cluster to authenticate against the server')
    auth_private_key = models.CharField('private key', max_length=256,
        help_text='Private key used to validate the request of the ')

    class Meta:
        abstract = False


class Fileserver_Shard(models.Model):
    """
    The shards. Container for files.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    title = models.CharField('Title', max_length=256)
    description = models.TextField('Description')

    active = models.BooleanField('Activated', default=True,
        help_text='Specifies if the shard is offline or online')

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
                              help_text='The cluster this shard belongs to')
    shard = models.ForeignKey(Fileserver_Shard, on_delete=models.CASCADE, related_name='links',
                              help_text='The shard this cluster belongs to')
    read = models.BooleanField('Read', default=True,
        help_text='Weather this shard accepts reads')
    write = models.BooleanField('Write', default=True,
        help_text='Weather this shard accepts writes')
    allow_link_shares = models.BooleanField('Allow link shares', default=True,
        help_text='Allows anonymous access with link shares')
    delete_capability = models.BooleanField('Delete', default=True,
        help_text='Weather this connection accepts deletes')

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
                              help_text='The cluster this member belongs to')
    public_key = models.CharField('public key', max_length=256,
        help_text='Public key of the member that is sent to the client')
    secret_key = models.CharField('Secret Key', max_length=256,
        help_text='Symmetric Key for the transport encryption')
    url = models.CharField('Public URL', max_length=256)
    version = models.CharField('Version', max_length=32)
    hostname = models.CharField('Hostname', max_length=256)
    read = models.BooleanField('Read', default=True,
        help_text='Weather this server accepts reads')
    write = models.BooleanField('Write', default=True,
        help_text='Weather this server accepts writes')
    allow_link_shares = models.BooleanField('Allow link shares', default=True,
        help_text='Allows anonymous access with link shares')
    delete_capability = models.BooleanField('Delete', default=True,
        help_text='Weather this server accepts deletes')

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

    title = models.CharField('title', max_length=256)
    type = models.CharField(max_length=32)

    active = models.BooleanField('Activated', default=False,
        help_text='Specifies if the file storage is active or not')

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

    read = models.BooleanField('Read', default=True,
        help_text='Weather this user can read the configured file repository details')
    write = models.BooleanField('Write', default=True,
        help_text='Weather this user can update the configured file repository')
    grant = models.BooleanField('Grant', default=True,
        help_text='Weather this user can change permissions and delete the configured file repository')
    accepted = models.BooleanField('Accepted', default=False,
                                   help_text='Defines if the file repository has been accepted or still waits for approval')


    class Meta:
        abstract = False


class Group_File_Repository_Right(models.Model):
    """
    The access permissions for group file repository config.

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

    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='file_repository_right')
    file_repository = models.ForeignKey(File_Repository, on_delete=models.CASCADE, related_name='group_file_repository_right')

    read = models.BooleanField('Read', default=True,
        help_text='Weather this user can read the configured file repository details')
    write = models.BooleanField('Write', default=True,
        help_text='Weather this user can update the configured file repository')
    grant = models.BooleanField('Grant', default=True,
        help_text='Weather this user can change permissions and delete the configured file repository')

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
                              help_text='The cluster member this link belongs to')
    shard = models.ForeignKey(Fileserver_Shard, on_delete=models.CASCADE, related_name='member_links',
                              help_text='The shard this link belongs to')
    read = models.BooleanField('Read', default=True,
        help_text='Weather this shard accepts reads')
    write = models.BooleanField('Write', default=True,
        help_text='Weather this shard accepts writes')
    allow_link_shares = models.BooleanField('Allow link shares', default=True,
        help_text='Allows anonymous access with link shares')
    delete_capability = models.BooleanField('Delete', default=True,
        help_text='Weather this shard accepts delete jobs')
    ip_read_whitelist = models.CharField('IP read whitelist', max_length=2048,
        help_text='IP Whitelist for read operations', null=True)
    ip_write_whitelist = models.CharField('IP write whitelist', max_length=2048,
        help_text='IP Whitelist for write operations', null=True)
    ip_read_blacklist = models.CharField('IP read blacklist', max_length=2048,
        help_text='IP Blacklist for read operations', null=True)
    ip_write_blacklist = models.CharField('IP write blacklist', max_length=2048,
        help_text='IP Blacklist for write operations', null=True)

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
    secret = models.ForeignKey(
        'Secret',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='attached_files',
        help_text='The secret this file is attached to (if it is an attachment)'
    )
    chunk_count = models.IntegerField('Chunk Count',
        help_text='The amount of chunks')
    size = models.BigIntegerField('Size',
        help_text='The size of the files in bytes (including encryption overhead)')

    delete_date = models.DateTimeField(null=True)

    def delete(self, *args, **kwargs):
        """
        Override delete to ensure proper cleanup of file storage.
        Handles both file repository (cloud storage) and shard (fileserver) cleanup.
        """
        # If file is stored in a file repository, delete all chunks from cloud storage
        if self.file_repository:
            from .utils import (
                decrypt_with_db_secret,
                gcs_delete,
                aws_delete,
                azure_blob_delete,
                do_delete,
                backblaze_delete,
                s3_delete,
                is_allowed_other_s3_endpoint_url
            )
            import json

            try:
                data = json.loads(decrypt_with_db_secret(self.file_repository.data))
                file_repository_type = self.file_repository.type

                for chunk in self.file_chunk.all():
                    try:
                        if file_repository_type == 'gcp_cloud_storage':
                            gcs_delete(data['gcp_cloud_storage_bucket'], data['gcp_cloud_storage_json_key'], chunk.hash_checksum)
                        elif file_repository_type == 'aws_s3':
                            aws_delete(data['aws_s3_bucket'], data['aws_s3_region'], data['aws_s3_access_key_id'], data['aws_s3_secret_access_key'], chunk.hash_checksum)
                        elif file_repository_type == 'azure_blob':
                            azure_blob_delete(data['azure_blob_storage_account_name'], data['azure_blob_storage_account_primary_key'], data['azure_blob_storage_account_container_name'], chunk.hash_checksum)
                        elif file_repository_type == 'do_spaces':
                            do_delete(data['do_space'], data['do_region'], data['do_key'], data['do_secret'], chunk.hash_checksum)
                        elif file_repository_type == 'backblaze':
                            backblaze_delete(data['backblaze_bucket'], data['backblaze_region'], data['backblaze_access_key_id'], data['backblaze_secret_access_key'], chunk.hash_checksum)
                        elif file_repository_type == 'other_s3' and is_allowed_other_s3_endpoint_url(data['other_s3_endpoint_url']):
                            s3_delete(data['other_s3_bucket'], data['other_s3_region'], data['other_s3_access_key_id'], data['other_s3_secret_access_key'], chunk.hash_checksum, endpoint_url=data['other_s3_endpoint_url'])
                    except: # nosec - Ignore individual chunk deletion failures
                        pass
            except: # nosec - Ignore failures to decrypt or parse repository data
                pass

        # For shard files, use soft delete (consistent with existing File_Link deletion behavior)
        elif self.shard and not self.delete_date:
            self.delete_date = timezone.now()
            self.save(update_fields=['delete_date'])
            return  # Don't call super().delete() for soft delete

        # Call parent delete to remove from database
        super().delete(*args, **kwargs)

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
                              help_text='The file, that this link links to.')
    link_id = models.UUIDField(unique=True)
    parent_share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='files', null=True,
                              help_text='The share, where this link ends and gets its permissions from')

    parent_datastore = models.ForeignKey(Data_Store, on_delete=models.CASCADE, related_name='files', null=True,
                                         help_text='The datastore, where this link ends')

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
        help_text='The position of the chunk in the file')
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='file_chunk')
    size = models.BigIntegerField('Size',
        help_text='The size of the chunk in bytes (including encryption overhead)')

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
    secret_key = models.CharField(max_length=64, default='')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='file_transfer')
    file = models.ForeignKey(File, on_delete=models.SET_NULL, null=True, related_name='file_transfer')
    shard = models.ForeignKey(Fileserver_Shard, on_delete=models.SET_NULL, null=True, related_name='file_transfer')
    file_repository = models.ForeignKey(File_Repository, on_delete=models.SET_NULL, null=True, related_name='file_transfer')
    type = models.CharField(max_length=8, default='download')
    credit = models.DecimalField(max_digits=24, decimal_places=16, default=Decimal(str(0)))

    size = models.BigIntegerField('Size',
                                  help_text='The amount in bytes that will be transferred (including encryption overhead)')

    size_transferred = models.BigIntegerField('Transferred Size',
                                              help_text='The amount in bytes that have been transferred (including encryption overhead)')
    chunk_count = models.IntegerField('Chunk Count',
        help_text='The amount of chunks')
    chunk_count_transferred = models.IntegerField('Chunk Count Transfered',
        help_text='The amount of chunks already transfered')


    def save(self, *args, **kwargs):
        if not self.secret_key:
            self.secret_key = nacl.encoding.HexEncoder.encode(
                nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            ).decode()

        return super(File_Transfer, self).save(*args, **kwargs)

    class Meta:
        abstract = False


class Link_Share(models.Model):
    """
    All the link shares
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='link_shares')
    secret = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name='link_shares', null=True)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='link_shares', null=True)
    public_title = models.CharField('Public Title', max_length=256)
    allow_write = models.BooleanField('Allow write', default=False, help_text='Do we allow people to update a secret')
    allowed_reads = models.IntegerField('Allowed reads or writes', blank=True, null=True,
                                        help_text='The remaining amount of allowed reads. Null if no restriction applies.')
    node = models.BinaryField()
    node_nonce = models.CharField('Node nonce', max_length=64)
    passphrase = models.CharField('Passphrase', max_length=128, blank=True, null=True)

    valid_till = models.DateTimeField(blank=True, null=True)

    class Meta:
        abstract = False


class SecurityReport(models.Model):
    """
    All the security reports send to the server
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_reports')
    recovery_code_exists = models.BooleanField('Recovery Code exists', default=False, help_text='Did a recovery code exist')
    two_factor_exists = models.BooleanField('Two factor exists', default=False, help_text='Did the user configure two factor exist')
    website_password_count = models.PositiveIntegerField('Count of passwords', default=0)
    breached_password_count = models.PositiveIntegerField('Count of breached passwords', default=0)
    duplicate_password_count = models.PositiveIntegerField('Count of password duplicates', default=0)
    check_haveibeenpwned = models.BooleanField('Checked HaveIBeenPwned', default=False, help_text='Did the user check his passwords against have i been pwened')

    master_password_breached = models.PositiveIntegerField('Master password breached', default=None, help_text='Has the master password been breached', null=True)
    master_password_duplicate = models.BooleanField('Master password duplicate', default=False, help_text='Has the master password been used somewhere else', null=True)
    master_password_length = models.PositiveIntegerField('Master password length', null=True)
    master_password_variation_count = models.PositiveIntegerField('Master password variation count', null=True, help_text='The count of variations (uppercase, lowercase, numbers, special chars')

    class Meta:
        abstract = False


class SecurityReportEntry(models.Model):
    """
    All the entries belonging to the security report
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    security_report = models.ForeignKey(SecurityReport, on_delete=models.CASCADE, related_name='security_report_entries')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_report_entries')
    name = models.TextField(null=True)
    type = models.TextField(null=True)
    create_age = models.DurationField('Create Age', help_text='The time in days since its last update', null=True)
    write_age = models.DurationField('Write Age', help_text='The time in days since its creation', null=True)
    master_password = models.BooleanField('Masterpassword', default=False, null=True)
    breached = models.PositiveIntegerField('Breached', default=None, null=True)
    duplicate = models.BooleanField('Duplicate', default=False, null=True)
    password_length = models.PositiveIntegerField('Password length', null=True)
    variation_count = models.PositiveIntegerField('Variation count', null=True, help_text='The count of variations (uppercase, lowercase, numbers, special chars')

    class Meta:
        abstract = False

class DeviceCode(models.Model):
    """
    The device code model to handle device authentication
    """

    class Meta:
        db_table = 'restapi_device_code'
        abstract = False

    class DeviceCodeState(models.TextChoices):
        PENDING = 'pending'
        CLAIMED = 'claimed'
        TOKEN_ISSUED = 'token_issued' #nosec B105
        EXPIRED = 'expired'
        FAILED = 'failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True, null=False, editable=False)
    write_date = models.DateTimeField(auto_now=True, null=False)
    valid_till = models.DateTimeField(default=timezone.now, editable=False, db_index=True)
    state = models.CharField(max_length=16, null=False, choices=DeviceCodeState.choices, default=DeviceCodeState.PENDING)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='device_codes', null=True)
    device_fingerprint = models.CharField(max_length=128, null=False, editable=False)
    device_description = models.CharField(max_length=256, null=True, editable=False)
    device_date = models.DateTimeField(null=True, editable=False)
    # server_private_key is stored encrypted with the db secret
    server_private_key = models.CharField(max_length=256, null=False, editable=False)
    server_public_key = models.CharField(max_length=128, null=False, editable=False)
    user_public_key = models.CharField(max_length=128, null=False, editable=False)
    encrypted_credentials = models.BinaryField(null=True, blank=True)
    encrypted_credentials_nonce = models.CharField(max_length=64, null=True, blank=True)

class Token(models.Model):
    """
    The custom authorization token model.
    """
    id = models.UUIDField(db_index=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    valid_till = models.DateTimeField(default=timezone.now)
    key = models.CharField(max_length=128, primary_key=True)
    session_key = models.CharField(max_length=64, null=True)
    secret_key = models.CharField(max_length=64)
    user_validator = models.CharField(max_length=64, null=True)
    device_fingerprint = models.CharField(max_length=128, null=True)
    device_description = models.CharField(max_length=256, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='auth_tokens')
    api_key = models.ForeignKey(API_Key, on_delete=models.CASCADE, null=True, related_name='tokens')
    read = models.BooleanField('Read', default=True, help_text='Read permissions')
    write = models.BooleanField('Write', default=True, help_text='Write permissions')
    active = models.BooleanField('Activated', default=False,
        help_text='Specifies if the token has already been activated')
    is_emergency_session = models.BooleanField('Is an emergency session', default=False,
        help_text='Specifies if the token has been created with an emergency code or not')
    google_authenticator_2fa = models.BooleanField('Google Authenticator Required', default=False,
        help_text='Specifies if Google Authenticator is required or not')

    yubikey_otp_2fa = models.BooleanField('Yubikey Required', default=False,
        help_text='Specifies if Yubikey is required or not')

    duo_2fa = models.BooleanField('Duo Required', default=False,
        help_text='Specifies if Duo is required or not')

    webauthn_2fa = models.BooleanField('Webauthn Required', default=False,
        help_text='Specifies if Webauthn is required or not')
    
    ivalt_2fa = models.BooleanField('ivalt Required', default=False,
        help_text='Specifies if ivalt is required or not')

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
        self.session_key = binascii.hexlify(os.urandom(32)).decode()

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

@receiver(pre_delete, sender=Secret)
def secret_pre_delete_receiver(sender, **kwargs):
    """
    Clean up attached files when a secret is deleted.
    This ensures the custom File.delete() method runs for proper cloud storage cleanup.
    """
    secret = kwargs['instance']
    # Manually delete each attached file to trigger custom delete() method
    for file in secret.attached_files.all():
        file.delete()
