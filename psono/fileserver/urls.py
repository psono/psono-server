from django.conf.urls import url
from django.conf import settings
from . import views
from django.urls import URLPattern
from typing import List

urlpatterns = [] # type: List[URLPattern]

if settings.FILESERVER_HANDLER_ENABLED:
    # URLs for fileserver communication only
    urlpatterns += [
        url(r'^alive/$', views.AliveView.as_view(), name='fileserver_alive'),
        url(r'^authorize/upload/$', views.AuthorizeUploadView.as_view(), name='fileserver_authorize_upload'),
        url(r'^authorize/download/$', views.AuthorizeDownloadView.as_view(), name='fileserver_authorize_download'),
    ]