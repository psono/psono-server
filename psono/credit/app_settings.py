from django.conf import settings

from importlib import import_module

# from .serializers import (
#     CreditAuthorizeUploadSerializer as DefaultCreditAuthorizeUploadSerializer,
# )

def import_callable(path_or_callable):
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        package, attr = path_or_callable.rsplit('.', 1)
        return getattr(import_module(package), attr)

serializers = getattr(settings, 'CREDIT_SERIALIZERS', {})

# CreditAuthorizeUploadSerializer = import_callable(
#     serializers.get('CREDIT_AUTHORIZE_UPLOAD_SERIALIZER', DefaultCreditAuthorizeUploadSerializer)
# )
