import binascii
import os
from hashlib import sha256
import uuid

from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _


class Data_Store_Owner(models.Model):
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
    private_key_nonce = models.CharField(_('private key nonce'), max_length=64)
    secret_key = models.CharField(_('secret key'), max_length=256)
    secret_key_nonce = models.CharField(_('secret key nonce'), max_length=64)
    is_email_active = models.BooleanField(_('email active'), default=False,
        help_text=_('Designates whether this email should be treated as '
                    'active. Unselect this if the user registers a new email.'))

    is_active = models.BooleanField(_('active'), default=True,
        help_text=_('Designates whether this owner should be treated as '
                    'active. Unselect this instead of deleting accounts.'))

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
    The data storage where all data of the user is saved
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(Data_Store_Owner, on_delete=models.CASCADE, related_name='data_store')
    data = models.BinaryField()
    type = models.CharField(max_length=64, db_index=True, default='password')
    description = models.CharField(max_length=64, default='default')

    class Meta:
        abstract = False


class Share(models.Model):
    """
    The share objects for shares between users. All data encoded.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(Data_Store_Owner, on_delete=models.CASCADE, related_name='share',
                              help_text=_('The share owner is always the same as the group owner, so the group '
                                          'owner always keeps full control.'))
    data = models.BinaryField()
    type = models.CharField(max_length=64, db_index=True, default='password')

    class Meta:
        abstract = False


class Group(models.Model):
    """
    The group object is the grouping object that glues shares and user rights together, the owner of the group
    automatically owns all shares. A share can only be shared with a second group, if the group owners are identical.
    If a share is shared with another person, a new group is created with the owner of the first group. This behaviour
    ensures full control for the group owner.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(Data_Store_Owner, on_delete=models.CASCADE, related_name='group')
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
        grant: Designates whether this user has "grant" rights and can add users and rights of users of this
            group. The user is limited by his own rights, so e.g. he cannot grant write if he does not have
            write on his own.
        revoke: Designates whether this user has "revoke" rights and can remove users and rights of users of
            this group. The owner of this group will always have full rights and cannot be shut out.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(Data_Store_Owner, on_delete=models.CASCADE, related_name='group_user_right')
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='group_user_right')

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
    revoke = models.BooleanField(_('revoke right'), default=False,
        help_text=_('Designates whether this user has "revoke" rights and can remove users and rights of users of '
                    'this group. The owner of this group will always have full rights and cannot be shut out.'))


    class Meta:
        abstract = False


@python_2_unicode_compatible
class Token(models.Model):
    """
    The custom authorization token model.
    """
    create_date = models.DateTimeField(auto_now_add=True)
    key = models.CharField(max_length=64, primary_key=True)
    owner = models.ForeignKey(Data_Store_Owner, related_name='auth_token')

    def save(self, *args, **kwargs):
        if not self.key:
            self._generate()
        return super(Token, self).save(*args, **kwargs)

    def _generate(self):
        # clear_text_key will not be saved in db but set as property so a "one-time-access" is possible while this
        # object instance is still alive
        self.clear_text_key = binascii.hexlify(os.urandom(32)).decode()
        self.key = sha256(self.clear_text_key).hexdigest()

    def __str__(self):
        return self.key

    class Meta:
        abstract = False

