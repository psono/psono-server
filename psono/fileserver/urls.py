from django.urls import re_path
from django.conf import settings
from . import views
from django.urls import URLPattern
from typing import List

urlpatterns = [] # type: List[URLPattern]

if settings.FILESERVER_HANDLER_ENABLED:
    # URLs for fileserver communication only
    urlpatterns += [
        re_path(r'^alive/$', views.AliveView.as_view(), name='fileserver_alive'),
        re_path(r'^upload/authorize/$', views.AuthorizeUploadView.as_view(), name='fileserver_authorize_upload'),
        re_path(r'^download/authorize/$', views.AuthorizeDownloadView.as_view(), name='fileserver_authorize_download'),
        re_path(r'^download/revoke/$', views.RevokeDownloadView.as_view(), name='fileserver_revoke_download'),
        re_path(r'^chunks/cleanup/$', views.CleanupChunksView.as_view(), name='fileserver_cleanup_chunks'),
    ]