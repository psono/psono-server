from django.conf import settings
from django.http import JsonResponse
from rest_framework import status

class DisableMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.DISABLED:
            return JsonResponse({"non_field_errors": ["SERVER_DISABLED"]}, status=status.HTTP_423_LOCKED)
        return self.get_response(request)

class MaintenanceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.MAINTENANCE_ACTIVE:
            return JsonResponse({"non_field_errors": ["MAINTENANCE_MODE_ACTIVE"]}, status=status.HTTP_423_LOCKED)
        return self.get_response(request)
