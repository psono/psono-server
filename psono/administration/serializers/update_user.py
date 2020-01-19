from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from rest_framework import serializers, exceptions
from restapi.fields import UUIDField, BooleanField
import bcrypt

from restapi.utils import encrypt_with_db_secret
from restapi.models import User

class UpdateUserSerializer(serializers.Serializer):
    user_id = UUIDField(required=True)
    is_active = BooleanField(required=False)
    is_email_active = BooleanField(required=False)
    is_superuser = BooleanField(required=False)
    email = serializers.EmailField(required=False, error_messages={ 'invalid': 'INVALID_EMAIL_FORMAT' })


    def validate(self, attrs: dict) -> dict:

        user_id = attrs.get('user_id')
        is_active = attrs.get('is_active', None)
        is_email_active = attrs.get('is_email_active', None)
        is_superuser = attrs.get('is_superuser', None)
        email = attrs.get('email')

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        if email is not None:

            email = email.lower().strip()

            if len(settings.REGISTRATION_EMAIL_FILTER) > 0:
                email_prefix, domain = email.split("@")
                if domain not in settings.REGISTRATION_EMAIL_FILTER:
                    msg = _('E-Mail not allowed to register.')
                    raise exceptions.ValidationError(msg)

            # generate bcrypt with static salt.
            # I know its bad to use static salts, but its the best solution I could come up with,
            # if you want to store emails encrypted while not having to decrypt all emails for duplicate email hunt
            # Im aware that this allows attackers with this fix salt to "mass" attack all emails.
            # if you have a better solution, please let me know.
            email_bcrypt_full = bcrypt.hashpw(email.encode(), settings.EMAIL_SECRET_SALT.encode())
            email_bcrypt = email_bcrypt_full.decode().replace(settings.EMAIL_SECRET_SALT, '', 1)

            if User.objects.filter(email_bcrypt=email_bcrypt).exclude(pk=user_id).exists():
                msg = _('E-Mail already exists.')
                raise exceptions.ValidationError(msg)

            attrs['email_bcrypt'] = email_bcrypt

            # normally encrypt emails, so they are not stored in plaintext with a random nonce
            email = encrypt_with_db_secret(email)


        attrs['user'] = user
        attrs['email'] = email
        attrs['is_active'] = is_active
        attrs['is_email_active'] = is_email_active
        attrs['is_superuser'] = is_superuser

        return attrs
