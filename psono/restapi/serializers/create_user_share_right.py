from ..utils import user_has_rights_on_share

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import User


class CreateUserShareRightSerializer(serializers.Serializer):
    key = serializers.CharField(max_length=256, required=False)
    key_nonce = serializers.CharField(max_length=64, required=False)
    title = serializers.CharField(max_length=512, required=False)
    title_nonce = serializers.CharField(max_length=64, required=False)
    type = serializers.CharField(max_length=512, required=False)
    type_nonce = serializers.CharField(max_length=64, required=False)
    share_id = serializers.UUIDField(required=True)
    user_id = serializers.UUIDField(required=True)
    read = serializers.BooleanField()
    write = serializers.BooleanField()
    grant = serializers.BooleanField()

    def validate(self, attrs):

        # check permissions on share
        if not user_has_rights_on_share(self.context['request'].user.id, attrs['share_id'], grant=True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # check if user exists
        try:
            attrs['user'] = User.objects.get(pk=attrs['user_id'])
        except User.DoesNotExist:
            msg = _('Target user does not exist.".')
            raise exceptions.ValidationError(msg)

        return attrs