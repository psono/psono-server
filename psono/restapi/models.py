from django.db.models.signals import post_save, post_init, post_delete
from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _
from django.dispatch import receiver
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone

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
    email = models.CharField(_('email address'), max_length=512, unique=True)
    email_bcrypt = models.CharField(_('bcrypt of email address'), max_length=60, unique=True)
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

    is_cachable = True
    #
    # __original_authkey = None
    # __original_public_key = None
    # __original_secret_key = None
    # __original_secret_key_nonce = None
    # __original_private_key = None
    # __original_private_key_nonce = None
    # __original_email = None
    # __original_email_bcrypt = None
    #
    # def __init__(self, *args, **kwargs):
    #     super(User, self).__init__(*args, **kwargs)
    #     self.__original_authkey = self.authkey
    #     self.__original_public_key = self.public_key
    #     self.__original_secret_key = self.secret_key
    #     self.__original_secret_key_nonce = self.secret_key_nonce
    #     self.__original_private_key = self.private_key
    #     self.__original_private_key_nonce = self.private_key_nonce
    #     self.__original_email = self.email
    #     self.__original_email_bcrypt = self.email_bcrypt

    # def save(self, *args, **kwargs):
    #
    #     authkey_changed = self.authkey != self.__original_authkey
    #     public_key_changed = self.public_key != self.__original_public_key
    #     secret_key_changed = self.secret_key != self.__original_secret_key
    #     secret_key_nonce_changed = self.secret_key_nonce != self.__original_secret_key_nonce
    #     private_key_changed = self.private_key != self.__original_private_key
    #     private_key_nonce_changed = self.private_key_nonce != self.__original_private_key_nonce
    #     email_changed = self.email != self.__original_email
    #     email_bcrypt_changed = self.email_bcrypt != self.__original_email_bcrypt
    #
    #     if authkey_changed or public_key_changed  or secret_key_changed  or secret_key_nonce_changed  or private_key_changed  or private_key_nonce_changed :
    #         Old_Credential.objects.create(
    #             user_id=self.id,
    #             authkey=self.__original_authkey,
    #             public_key=self.__original_public_key,
    #             secret_key=self.__original_secret_key,
    #             secret_key_nonce=self.__original_secret_key_nonce,
    #             private_key=self.__original_private_key,
    #             private_key_nonce=self.__original_private_key_nonce,
    #         )
    #
    #     if email_changed or email_bcrypt_changed :
    #         Old_Email.objects.create(
    #             user_id=self.id,
    #             email=self.__original_email,
    #             email_bcrypt=self.__original_email_bcrypt,
    #         )
    #
    #     super(User, self).save(*args, **kwargs)
    #
    #     self.__original_authkey = self.authkey
    #     self.__original_public_key = self.public_key
    #     self.__original_secret_key = self.secret_key
    #     self.__original_secret_key_nonce = self.secret_key_nonce
    #     self.__original_private_key = self.private_key
    #     self.__original_private_key_nonce = self.private_key_nonce
    #     self.__original_email = self.email
    #     self.__original_email_bcrypt = self.email_bcrypt

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
        except User.DoesNotExist:
            pass

        super(User, self).save(*args, **kwargs)

    # @staticmethod
    # def post_save(sender, **kwargs):
    #     instance = kwargs.get('instance')
    #     created = kwargs.get('created', False)
    #
    #     authkey_changed = instance.authkey != instance.__original_authkey
    #     public_key_changed = instance.public_key != instance.__original_public_key
    #     secret_key_changed = instance.secret_key != instance.__original_secret_key
    #     secret_key_nonce_changed = instance.secret_key_nonce != instance.__original_secret_key_nonce
    #     private_key_changed = instance.private_key != instance.__original_private_key
    #     private_key_nonce_changed = instance.private_key_nonce != instance.__original_private_key_nonce
    #     email_changed = instance.email != instance.__original_email
    #     email_bcrypt_changed = instance.email_bcrypt != instance.__original_email_bcrypt
    #
    #     if not created and (authkey_changed or public_key_changed  or secret_key_changed  or secret_key_nonce_changed  or private_key_changed  or private_key_nonce_changed) :
    #         Old_Credential.objects.create(
    #             user_id=instance.id,
    #             authkey=instance.__original_authkey,
    #             public_key=instance.__original_public_key,
    #             secret_key=instance.__original_secret_key,
    #             secret_key_nonce=instance.__original_secret_key_nonce,
    #             private_key=instance.__original_private_key,
    #             private_key_nonce=instance.__original_private_key_nonce,
    #         )
    #
    #     if not created and (email_changed or email_bcrypt_changed) :
    #         Old_Email.objects.create(
    #             user_id=instance.id,
    #             email=instance.__original_email,
    #             email_bcrypt=instance.__original_email_bcrypt,
    #         )
    #
    # @staticmethod
    # def remember_state(sender, **kwargs):
    #     instance = kwargs.get('instance')
    #     instance.__original_authkey = instance.authkey
    #     instance.__original_public_key = instance.public_key
    #     instance.__original_secret_key = instance.secret_key
    #     instance.__original_secret_key_nonce = instance.secret_key_nonce
    #     instance.__original_private_key = instance.private_key
    #     instance.__original_private_key_nonce = instance.private_key_nonce
    #     instance.__original_email = instance.email
    #     instance.__original_email_bcrypt = instance.email_bcrypt

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

# post_save.connect(User.post_save, sender=User)
# post_init.connect(User.remember_state, sender=User)

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
    email_bcrypt = models.CharField(_('bcrypt of email address'), max_length=60, unique=True)

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
    write = models.BooleanField(_('Wright right'), default=False,
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
                                      help_text=_('Designates whether this user can invite other users to this group, and adjust other user rights'))
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
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='auth_tokens')
    active = models.BooleanField(_('Activated'), default=False,
        help_text=_('Specifies if the token has already been activated'))
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

