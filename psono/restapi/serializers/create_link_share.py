from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.auth.hashers import make_password

from rest_framework import serializers, exceptions

from ..fields import UUIDField
from ..utils import user_has_rights_on_secret, user_has_rights_on_file

class CreateLinkShareSerializer(serializers.Serializer):

    secret_id = UUIDField(required=False)
    file_id = UUIDField(required=False)

    node = serializers.CharField(required=True)
    node_nonce = serializers.CharField(max_length=64, required=True)
    public_title = serializers.CharField(max_length=256, required=True)

    # allowed_reads > 0 => restrict reads to allowed_reads times
    # allowed_reads not provided => No restriction
    allowed_reads = serializers.IntegerField(required=False, min_value=0, allow_null=True)

    # passphrase is None => passphrase = ''
    # passphrase = '' => same
    # passphrase = '....' =>
    passphrase = serializers.CharField(required=False, allow_null=True, allow_blank=True)

    # valid_till is None => No restriction time wise
    # else => set restriciton
    valid_till = serializers.DateTimeField(required=False, allow_null=True)

    def validate(self, attrs: dict) -> dict:

        secret_id = attrs.get('secret_id', None)
        file_id = attrs.get('file_id', None)
        allowed_reads = attrs.get('allowed_reads', None)
        passphrase = attrs.get('passphrase', None)
        valid_till = attrs.get('valid_till', None)

        if not secret_id and not file_id:
            msg = "EITHER_SECRET_OR_FILE_REQUIRED"
            raise exceptions.ValidationError(msg)

        if secret_id and file_id:
            msg = "EITHER_SECRET_OR_FILE_REQUIRED_NOT_BOTH"
            raise exceptions.ValidationError(msg)

        if secret_id and not user_has_rights_on_secret(self.context['request'].user.id, secret_id):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check if the user has the necessary rights
        if file_id and not user_has_rights_on_file(self.context['request'].user.id, file_id, read=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if valid_till is not None and valid_till < timezone.now():
            msg = "VALID_TILL_CANNOT_BE_IN_THE_PAST"
            raise exceptions.ValidationError(msg)

        if passphrase == '':  #nosec -- not [B105:hardcoded_password_string]
            passphrase = None
        if passphrase is not None:
            passphrase = make_password(passphrase)

        attrs['secret_id'] = secret_id
        attrs['file_id'] = file_id
        attrs['allowed_reads'] = allowed_reads
        attrs['passphrase'] = passphrase
        attrs['valid_till'] = valid_till

        return attrs