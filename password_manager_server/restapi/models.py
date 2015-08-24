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
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    email = models.EmailField(_('email address'), unique=True)
    authkey = models.CharField(_('auth key'), max_length=128)
    is_email_active = models.BooleanField(_('email active'), default=False,
        help_text=_('Designates whether this email should be treated as '
                    'active. Unselect this if the user registers a new email.'))

    is_active = models.BooleanField(_('active'), default=True,
        help_text=_('Designates whether this owner should be treated as '
                    'active. Unselect this instead of deleting accounts.'))

    class Meta:
        abstract = False


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

