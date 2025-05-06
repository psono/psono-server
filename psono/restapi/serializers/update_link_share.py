from django.utils import timezone
from django.contrib.auth.hashers import make_password
from rest_framework import serializers, exceptions

from ..utils import user_has_rights_on_secret
from ..fields import UUIDField
from ..models import Link_Share

class UpdateLinkShareSerializer(serializers.Serializer):

    link_share_id = UUIDField(required=True)
    public_title = serializers.CharField(required=True)

    # allowed_reads > 0 => restrict reads to allowed_reads times
    # allowed_reads not provided => No restriction
    allowed_reads = serializers.IntegerField(required=False, min_value=0, allow_null=True)

    # passphrase not provided => no change
    # passphrase == '' => empty pass
    # else => New passphrase
    passphrase = serializers.CharField(required=False, allow_null=True, allow_blank=True)

    # valid_till not provided => no restriction anymore
    # else => update restriction
    valid_till = serializers.DateTimeField(required=False, allow_null=True)

    allow_write = serializers.DateTimeField(required=False, allow_null=True)

    def validate(self, attrs: dict) -> dict:

        link_share_id = attrs.get('link_share_id')
        allowed_reads = attrs.get('allowed_reads', None)
        passphrase = attrs.get('passphrase', None)
        valid_till = attrs.get('valid_till', None)
        allow_write = attrs.get('allow_write', None)

        # Lets check if the current user can do that
        try:
            link_share = Link_Share.objects.get(id=link_share_id, user=self.context['request'].user)
        except Link_Share.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if link_share.secret_id is not None and allow_write and not user_has_rights_on_secret(self.context['request'].user.id, link_share.secret_id,
                                                           write=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if valid_till is not None and valid_till < timezone.now():
            msg = "VALID_TILL_CANNOT_BE_IN_THE_PAST"
            raise exceptions.ValidationError(msg)

        if passphrase == '':  #nosec -- not [B105:hardcoded_password_string]
            passphrase = None
        elif passphrase is None:
            passphrase = link_share.passphrase
        else:
            passphrase = make_password(passphrase)

        attrs['link_share'] = link_share
        attrs['allowed_reads'] = allowed_reads
        attrs['passphrase'] = passphrase
        attrs['valid_till'] = valid_till

        return attrs
