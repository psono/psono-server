"""psono URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import url
from django.conf import settings
from . import views
from django.urls import URLPattern
from typing import List

urlpatterns = [] # type: List[URLPattern]

if settings.FILESERVER_HANDLER_ENABLED:
    # URLs for fileserver handling servers only
    urlpatterns += [
        url(r'^alive/$', views.AliveView.as_view(), name='fileserver_alive'),
    ]