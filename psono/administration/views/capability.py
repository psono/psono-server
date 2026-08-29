from administration.permissions import AdminPermission
from administration.utils.capabilities import capabilities_as_dicts
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from restapi.authentication import TokenAuthentication


class CapabilityView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)

    def get(self, request):
        return Response({"capabilities": capabilities_as_dicts()})
