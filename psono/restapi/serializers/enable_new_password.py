try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from rest_framework import serializers



class EnableNewPasswordSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'Enter a valid username' })
    recovery_authkey = serializers.CharField(required=True)