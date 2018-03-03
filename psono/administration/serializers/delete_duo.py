from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions

from restapi.models import Duo

class DeleteDuoSerializer(serializers.Serializer):
    duo_id = serializers.UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        duo_id = attrs.get('duo_id')

        try:
            duo = Duo.objects.get(pk=duo_id)
        except Duo.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['duo'] = duo

        return attrs
