import nacl.encoding
import secrets
import string
from django.conf import settings
from nacl.public import PrivateKey
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import GenerateFileserverClusterConfigSerializer
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.utils import decrypt_with_db_secret


class FileserverClusterConfigView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    allowed_methods = ("POST", "OPTIONS", "HEAD")
    serializer_class = GenerateFileserverClusterConfigSerializer

    def post(self, request, *args, **kwargs):
        """
        Generates a configuration for a member of a fileserver cluster
        """

        serializer = GenerateFileserverClusterConfigSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        cluster = serializer.validated_data.get("cluster")

        private_key = PrivateKey.generate()
        private_key_hex = private_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        public_key_hex = private_key.public_key.encode(
            encoder=nacl.encoding.HexEncoder
        ).decode()

        alphabet = string.ascii_letters + string.digits + string.punctuation
        secret_key = "".join(secrets.choice(alphabet) for _ in range(50)).replace(
            "'", '"'
        )

        shards = []
        for link in cluster.links.order_by("shard_id"):
            shards.append(
                "{shard_id: "
                + str(link.shard_id)
                + ", read: "
                + str(link.read)
                + ", write: "
                + str(link.write)
                + ", delete: "
                + str(link.delete_capability)
                + ", allow_link_shares: "
                + str(link.allow_link_shares)
                + ", engine: {class: 'local', kwargs: {location: '/opt/psono-shard/"
                + str(link.shard_id)
                + "'}}}"
            )

        configuration = "\n".join(
            [
                "SECRET_KEY: " + repr(secret_key),
                "PRIVATE_KEY: " + repr(private_key_hex),
                "PUBLIC_KEY: " + repr(public_key_hex),
                "SERVER_URL: " + repr(settings.HOST_URL),
                "SERVER_PUBLIC_KEY: " + repr(settings.PUBLIC_KEY),
                "CLUSTER_ID: '" + str(cluster.id) + "'",
                "CLUSTER_PRIVATE_KEY: '"
                + str(decrypt_with_db_secret(cluster.auth_private_key))
                + "'",
                "SHARDS: [" + ",".join(shards) + "]",
            ]
        )

        response = Response({"configuration": configuration}, status=status.HTTP_200_OK)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"

        return response
