try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder


from rest_framework import serializers


class SecretSerializer(serializers.Serializer):

    create_date = serializers.DateTimeField()
    write_date = serializers.DateTimeField()
    data = serializers.CharField()
    data_nonce = serializers.CharField(max_length=64)
    type = serializers.CharField(max_length=64, default='password')