try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions

from ..models import User_Share_Right

class ShareRightDeclineSerializer(serializers.Serializer):

    share_right_id = serializers.UUIDField(required=True)

    def validate(self, attrs):

        share_right_id = attrs.get('share_right_id')

        try:
            user_share_right_obj = User_Share_Right.objects.get(pk=share_right_id, user=self.context['request'].user, accepted=None)
        except User_Share_Right.DoesNotExist:
            msg = _("You don't have permission to access it or it does not exist or you already accepted or declined this share.")
            raise exceptions.ValidationError(msg)

        attrs['user_share_right_obj'] = user_share_right_obj

        return attrs