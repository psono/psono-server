from django.utils.translation import gettext_lazy as _
from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import User

class DeleteUserSerializer(serializers.Serializer):
    user_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        user_id = attrs.get('user_id')

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['user'] = user

        return attrs
