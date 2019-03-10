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

if settings.MANAGEMENT_ENABLED:
    # URLs for management servers purposes only
    urlpatterns += [
        url(r'^info/$', views.InfoView.as_view(), name='admin_info'),
        url(r'^user/(?P<user_id>[^/]+)/$', views.UserView.as_view(), name='admin_user'),
        url(r'^user/$', views.UserView.as_view(), name='admin_user'),
        url(r'^yubikey-otp/$', views.YubikeyOTPView.as_view(), name='admin_yubikey_otp'),
        url(r'^google-authenticator/$', views.GaView.as_view(), name='admin_google_authenticator'),
        url(r'^recovery-code/$', views.RecoveryCodeView.as_view(), name='admin_recovery_code'),
        url(r'^duo/$', views.DuoView.as_view(), name='admin_duo'),
        url(r'^session/(?P<session_id>[^/]+)/$', views.SessionView.as_view(), name='admin_session'),
        url(r'^session/$', views.SessionView.as_view(), name='admin_session'),
        url(r'^group/(?P<group_id>[^/]+)/$', views.GroupView.as_view(), name='admin_group'),
        url(r'^group/$', views.GroupView.as_view(), name='admin_group'),
        url(r'^membership/$', views.MembershipView.as_view(), name='admin_membership'),
    ]