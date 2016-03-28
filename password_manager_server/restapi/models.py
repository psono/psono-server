import binascii
import os
from hashlib import sha512
import uuid

from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _


class User(models.Model):
    """
    The custom user who owns the data storage
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    email = models.EmailField(_('email address'), unique=True)
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

    class Meta:
        abstract = False

    @staticmethod
    def is_authenticated():
        """
        Always return True. This is a way to tell if the user has been
        authenticated.
        """
        return True


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
    data_nonce = models.CharField(_('data nonce'), max_length=64)
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
    Once it gets declined it gets deleted.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='own_user_share_rights',
                              help_text=_('The guy who created this share'))
    title = models.CharField(_('Title'), max_length=256,
                             help_text=_('The public title of the share.'),
                             null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='foreign_user_share_rights',
                              help_text=_('The guy who will receive this share'))
    share = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='user_share_rights',
                              help_text=_('The guy who created this share'))
    key = models.CharField(_('Key'), max_length=256,
                           help_text=_('The (public or secret) encrypted key with which the share is encrypted.'))
    key_nonce = models.CharField(_('Key nonce'), max_length=64)
    read = models.BooleanField(_('Read right'), default=True,
        help_text=_('Designates whether this user has "read" rights and can read this share'))
    write = models.BooleanField(_('Wright right'), default=False,
        help_text=_('Designates whether this user has "write" rights and can update this share'))
    grant = models.BooleanField(_('Grant right'), default=False,
        help_text=_('Designates whether this user has "grant" rights and can re-share this share'))

    class Meta:
        abstract = False
        unique_together = ('user', 'share',)


@python_2_unicode_compatible
class Token(models.Model):
    """
    The custom authorization token model.
    """
    create_date = models.DateTimeField(auto_now_add=True)
    key = models.CharField(max_length=128, primary_key=True)
    user = models.ForeignKey(User, related_name='auth_tokens')

    def save(self, *args, **kwargs):
        if not self.key:
            self._generate()
        return super(Token, self).save(*args, **kwargs)

    def _generate(self):
        # clear_text_key will not be saved in db but set as property so a "one-time-access" is possible while this
        # object instance is still alive
        self.clear_text_key = binascii.hexlify(os.urandom(64)).decode()
        self.key = sha512(self.clear_text_key).hexdigest()

    def __str__(self):
        return self.key

    class Meta:
        abstract = False

