try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions

from ..models import User


class UserSearchSerializer(serializers.Serializer):

    user_id = serializers.UUIDField(required=False)
    user_username = serializers.CharField(required=False)

    def validate(self, attrs):

        user_id = attrs.get('user_id', False)
        user_username = attrs.get('user_username', False)


        if user_id:
            try:
                user = User.objects.get(pk=str(user_id))
            except User.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        elif user_username:
            try:
                user = User.objects.get(username=str(user_username))

            except User.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)
        else:
            msg = _("Either user id or username need to be specified.")
            raise exceptions.ValidationError(msg)


        attrs['user'] = user

        return attrs
