from django.conf import settings

from importlib import import_module

from .serializers import (
    AuthorizeUploadSerializer as DefaultAuthorizeUploadSerializer,
    FileserverAliveSerializer as DefaultFileserverAliveSerializer,
)

def import_callable(path_or_callable):
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        package, attr = path_or_callable.rsplit('.', 1)
        return getattr(import_module(package), attr)

serializers = getattr(settings, 'FILESERVER_SERIALIZERS', {})

AuthorizeUploadSerializer = import_callable(
    serializers.get('AUTHORIZE_UPLOAD_SERIALIZER', DefaultAuthorizeUploadSerializer)
)


FileserverAliveSerializer = import_callable(
    serializers.get('FILESERVER_ALIVE_SERIALIZER', DefaultFileserverAliveSerializer)
)

