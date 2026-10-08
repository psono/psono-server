from django.contrib.auth.hashers import make_password
from django.db import transaction
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.serializers import Serializer

from ..app_settings import UserUpgradeHashingSerializer
from ..authentication import TokenAuthentication
from ..models import User
from ..permissions import IsAuthenticated


class UserUpgradeHashingView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    allowed_methods = ("PUT", "OPTIONS", "HEAD")
    throttle_scope = "user_update"

    def get_serializer_class(self):
        if self.request.method == "PUT":
            return UserUpgradeHashingSerializer
        return Serializer

    @transaction.atomic
    def put(self, request, *args, **kwargs):
        """Upgrade the account's hashing parameters."""
        request.user = User.objects.select_for_update().get(pk=request.user.pk)
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        for name in (
            "private_key",
            "private_key_nonce",
            "secret_key",
            "secret_key_nonce",
            "hashing_algorithm",
            "hashing_parameters",
        ):
            setattr(request.user, name, data[name])
        request.user.authkey = make_password(data["authkey"])
        request.user.save()
        return Response({"success": "Hashing parameters upgraded."})
