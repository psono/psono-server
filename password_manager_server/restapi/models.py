import binascii
import os

from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _


class Content_Storage_Owner(models.Model):
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


class Content_Storage(models.Model):
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(Content_Storage_Owner, on_delete=models.CASCADE)
    data = models.BinaryField()

    class Meta:
        abstract = False


@python_2_unicode_compatible
class Token(models.Model):
    """
    The custom authorization token model.
    """
    create_date = models.DateTimeField(auto_now_add=True)
    key = models.CharField(max_length=40, primary_key=True)
    owner = models.OneToOneField(Content_Storage_Owner, related_name='auth_token')

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(Token, self).save(*args, **kwargs)

    def generate_key(self):
        return binascii.hexlify(os.urandom(20)).decode()

    def __str__(self):
        return self.key

    class Meta:
        abstract = False

