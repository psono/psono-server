"""password_manager_server URL Configuration

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
import django
import views

urlpatterns = [
    # URLs that do not require a session or valid token
    #url(r'^authentication/authkey/reset/$', views.AuthkeyResetView.as_view(),
    #    name='authentication_authkey_reset'),
    #url(r'^authentication/authkey/reset/confirm/$', views.AuthkeyResetConfirmView.as_view(),
    #    name='authentication_authkey_reset_confirm'),
    url(r'^authentication/login/$', views.LoginView.as_view(), name='authentication_login'),
    url(r'^authentication/logout/$', views.LogoutView.as_view(), name='authentication_logout'),
    url(r'^authentication/activate-token/$', views.ActivateTokenView.as_view(), name='authentication_activate_token'),
    url(r'^authentication/register/$', views.RegisterView.as_view(), name='authentication_register'),
    url(r'^authentication/verify-email/$', views.VerifyEmailView.as_view(), name='authentication_verify_email'),

    url(r'^user/update/$', views.UserUpdate.as_view(), name='user_update'),
    url(r'^user/search/$', views.UserSearch.as_view(), name='user_search'),

    url(r'^datastore/$', views.DatastoreView.as_view(), name='datastore'),
    url(r'^datastore/(?P<uuid>[^/]+)/$', views.DatastoreView.as_view(), name='datastore'),

    url(r'^secret/$', views.SecretView.as_view(), name='secret'),
    url(r'^secret/(?P<uuid>[^/]+)/$', views.SecretView.as_view(), name='secret'),

    url(r'^share/rights/(?P<uuid>[^/]+)/$', views.ShareRightsView.as_view(), name='share_rights'),

    url(r'^share/right/accept/$', views.ShareRightAcceptView.as_view(), name='share_right_accept'),
    url(r'^share/right/accept/(?P<uuid>[^/]+)/$', views.ShareRightAcceptView.as_view(), name='share_right_accept'),
    url(r'^share/right/decline/$', views.ShareRightDeclineView.as_view(), name='share_right_decline'),
    url(r'^share/right/decline/(?P<uuid>[^/]+)/$', views.ShareRightDeclineView.as_view(), name='share_right_decline'),
    url(r'^share/right/$', views.ShareRightView.as_view(), name='share_right'),
    url(r'^share/right/(?P<uuid>[^/]+)/$', views.ShareRightView.as_view(), name='share_right'),

    url(r'^share/link/$', views.ShareLinkView.as_view(), name='share_link'),
    url(r'^share/link/(?P<uuid>[^/]+)/$', views.ShareLinkView.as_view(), name='share_link'),

    url(r'^share/$', views.ShareView.as_view(), name='share'),
    url(r'^share/(?P<uuid>[^/]+)/$', views.ShareView.as_view(), name='share'),

    url(r'^group/$', views.GroupView.as_view(), name='group'),
    url(r'^group/(?P<uuid>[^/]+)/$', views.GroupView.as_view(), name='group'),

    # url(r'^$', views.api_root),
]

if settings.DEBUG:
    # URLs for development purposes only
    urlpatterns += [
        url(r'^demo/(?P<path>.*)$', django.views.static.serve,
            {'document_root':'/home/chickahoona/gits/password-manager-server/demo'}),
    ]