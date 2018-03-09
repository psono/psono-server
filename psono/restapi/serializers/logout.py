from django.utils.translation import ugettext_lazy as _
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
                attrs['token'] = Token.objects.get(id=session_id, user=self.context['request'].user)
            except Token.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)
        else:
            attrs['token'] = self.context['request'].auth

        return attrs