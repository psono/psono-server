from rest_framework.throttling import AnonRateThrottle as OrigAnonRateThrottle
from rest_framework.throttling import UserRateThrottle as OrigUserRateThrottle
from rest_framework.throttling import ScopedRateThrottle as OrigScopedRateThrottle
from django.conf import settings

class AnonRateThrottle(OrigAnonRateThrottle):

    def get_ident(self, request):
        if settings.TRUSTED_IP_HEADER and request.META.get(settings.TRUSTED_IP_HEADER, None):
            remote_addr = request.META.get(settings.TRUSTED_IP_HEADER, None)
        else:
            remote_addr = super().get_ident(request)

        return remote_addr

class UserRateThrottle(OrigUserRateThrottle):

    def get_ident(self, request):
        if settings.TRUSTED_IP_HEADER and request.META.get(settings.TRUSTED_IP_HEADER, None):
            remote_addr = request.META.get(settings.TRUSTED_IP_HEADER, None)
        else:
            remote_addr = super().get_ident(request)

        return remote_addr

class ScopedRateThrottle(OrigScopedRateThrottle):

    def get_ident(self, request):
        if settings.TRUSTED_IP_HEADER and request.META.get(settings.TRUSTED_IP_HEADER, None):
            remote_addr = request.META.get(settings.TRUSTED_IP_HEADER, None)
        else:
            remote_addr = super().get_ident(request)

        return remote_addr

