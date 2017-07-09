from django.conf import settings

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder


from rest_framework import serializers


class DeleteDatastoreSerializer(serializers.Serializer):

    datastore_id = serializers.UUIDField(required=True)
    authkey = serializers.CharField(style={'input_type': 'password'}, required=True,
                                    max_length=settings.AUTH_KEY_LENGTH_BYTES*2,
                                    min_length=settings.AUTH_KEY_LENGTH_BYTES*2)