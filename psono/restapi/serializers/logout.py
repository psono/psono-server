from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers

from ..models import (
    Token
)

class LogoutSerializer(serializers.Serializer):
    session_id = serializers.CharField(required=False)

    def validate(self, attrs: dict) -> dict:
        session_id = attrs.get('session_id', False)

        if session_id:
            try:
                token = Token.objects.get(id=session_id, user=self.context['request'].user)
            except Token.DoesNotExist:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)
        else:
            token = self.context['request'].auth

        attrs['token'] = token

        return attrs