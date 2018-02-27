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

urlpatterns = []

if settings.MANAGEMENT_ENABLED:
    # URLs for development purposes only
    urlpatterns += [
        url(r'^info/$', views.InfoView.as_view(), name='admin_info'),
        url(r'^user/(?P<user_id>[^/]+)/$', views.UserView.as_view(), name='admin_user'),
        url(r'^user/$', views.UserView.as_view(), name='admin_user'),
        url(r'^session/(?P<session_id>[^/]+)/$', views.SessionView.as_view(), name='admin_session'),
        url(r'^session/$', views.SessionView.as_view(), name='admin_session'),
    ]