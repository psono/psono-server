from django.conf.urls import url
from django.conf import settings
from . import views
from django.urls import URLPattern
from typing import List

urlpatterns = [] # type: List[URLPattern]

if settings.CREDIT_HANDLER_ENABLED:
    # URLs for credit communication only
    urlpatterns += [
        # url(r'^authorize/upload/$', views.AuthorizeUploadView.as_view(), name='credit_authorize_upload'),
    ]