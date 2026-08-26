from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import DeleteEmergencyCodeSerializer

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Emergency_Code
from administration.serializers.read_administration import ReadRecoveryCodeSerializer


class EmergencyCodeView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    serializer_class = DeleteEmergencyCodeSerializer
    allowed_methods = ("DELETE", "OPTIONS", "HEAD")

    def get_serializer_class(self):
        if self.request.method == "DELETE":
            return DeleteEmergencyCodeSerializer
        return ReadRecoveryCodeSerializer

    def get(self, request, *args, **kwargs):
        """
        Returns a list of all emergency codes
        """

        serializer = ReadRecoveryCodeSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        access = serializer.validated_data["admin_access"]
        queryset = Emergency_Code.objects.select_related("user").order_by(
            "-create_date"
        )
        queryset = access.filter_user_relations(queryset)
        emergency_codes = []
        for g in queryset:
            emergency_codes.append(
                {
                    "id": g.id,
                    "create_date": g.create_date,
                    "user": g.user.username,
                    "description": g.description,
                }
            )

        return Response({"emergency_codes": emergency_codes}, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a Emergency Code
        """

        serializer = DeleteEmergencyCodeSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        emergency_code = serializer.validated_data.get("emergency_code")

        # delete it
        emergency_code.delete()

        return Response({}, status=status.HTTP_200_OK)
