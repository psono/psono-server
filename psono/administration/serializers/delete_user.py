from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions

from restapi.models import User

class DeleteUserSerializer(serializers.Serializer):
    user_id = serializers.UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        user_id = attrs.get('user_id')

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['user'] = user

        return attrs
