from django.conf import settings

from importlib import import_module

# from .serializers import (
#     FileserverAuthorizeUploadSerializer as DefaultFileserverAuthorizeUploadSerializer,
#     FileserverAuthorizeDownloadSerializer as DefaultFileserverAuthorizeDownloadSerializer,
#     FileserverAliveSerializer as DefaultFileserverAliveSerializer,
#     FileserverConfirmChunkDeletionSerializer as DefaultFileserverConfirmChunkDeletionSerializer,
# )

def import_callable(path_or_callable):
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        package, attr = path_or_callable.rsplit('.', 1)
        return getattr(import_module(package), attr)

serializers = getattr(settings, 'CREDIT_SERIALIZERS', {})

# FileserverAuthorizeUploadSerializer = import_callable(
#     serializers.get('CREDIT_AUTHORIZE_UPLOAD_SERIALIZER', DefaultFileserverAuthorizeUploadSerializer)
# )
#
# FileserverAuthorizeDownloadSerializer = import_callable(
#     serializers.get('CREDIT_AUTHORIZE_DOWNLOAD_SERIALIZER', DefaultFileserverAuthorizeDownloadSerializer)
# )
#
#
# FileserverAliveSerializer = import_callable(
#     serializers.get('CREDIT_ALIVE_SERIALIZER', DefaultFileserverAliveSerializer)
# )
#
#
# FileserverConfirmChunkDeletionSerializer = import_callable(
#     serializers.get('CREDIT_CONFIRM_CHUNK_DELETION_SERIALIZER', DefaultFileserverConfirmChunkDeletionSerializer)
# )

