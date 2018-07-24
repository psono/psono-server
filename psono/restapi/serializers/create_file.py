from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Fileserver_Shard

class CreateFileSerializer(serializers.Serializer):

    shard_id = UUIDField(required=True)
    chunk_count = serializers.IntegerField(required=False)
    size = serializers.IntegerField(required=False)

    def validate(self, attrs: dict) -> dict:

        shard_id = attrs.get('shard_id')

        # check if the shard exists
        try:
            shard = Fileserver_Shard.objects.only('id').get(pk=shard_id)
        except Fileserver_Shard.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)



        attrs['shard'] = shard

        return attrs

