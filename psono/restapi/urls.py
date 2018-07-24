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
from os.path import join, dirname, abspath
import django
from . import views

urlpatterns = [
    # URLs that do not require a session or valid token
    #url(r'^authentication/authkey/reset/$', views.AuthkeyResetView.as_view(),
    #    name='authentication_authkey_reset'),
    #url(r'^authentication/authkey/reset/confirm/$', views.AuthkeyResetConfirmView.as_view(),
    #    name='authentication_authkey_reset_confirm'),
    url(r'^authentication/login/$', views.LoginView.as_view(), name='authentication_login'),
    url(r'^authentication/logout/$', views.LogoutView.as_view(), name='authentication_logout'),
    url(r'^authentication/ga-verify/$', views.GAVerifyView.as_view(), name='authentication_ga_verify'),
    url(r'^authentication/duo-verify/$', views.DuoVerifyView.as_view(), name='authentication_duo_verify'),
    url(r'^authentication/yubikey-otp-verify/$', views.YubikeyOTPVerifyView.as_view(), name='authentication_yubikey_otp_verify'),
    url(r'^authentication/activate-token/$', views.ActivateTokenView.as_view(), name='authentication_activate_token'),
    url(r'^authentication/sessions/$', views.SessionView.as_view(), name='authentication_session'),

    url(r'^authentication/register/$', views.RegisterView.as_view(), name='authentication_register'),
    url(r'^authentication/verify-email/$', views.VerifyEmailView.as_view(), name='authentication_verify_email'),

    url(r'^user/update/$', views.UserUpdate.as_view(), name='user_update'),
    url(r'^user/ga/$', views.UserGA.as_view(), name='user_ga'),
    url(r'^user/duo/$', views.UserDuo.as_view(), name='user_duo'),
    url(r'^user/yubikey-otp/$', views.UserYubikeyOTP.as_view(), name='user_yubikey_otp'),
    url(r'^user/search/$', views.UserSearch.as_view(), name='user_search'),
    url(r'^user/delete/$', views.UserDelete.as_view(), name='user_delete'),

    url(r'^password/$', views.PasswordView.as_view(), name='password'),
    url(r'^recoverycode/$', views.RecoveryCodeView.as_view(), name='recoverycode'),

    url(r'^datastore/$', views.DatastoreView.as_view(), name='datastore'),
    url(r'^datastore/(?P<datastore_id>[^/]+)/$', views.DatastoreView.as_view(), name='datastore'),

    url(r'^secret/link/$', views.SecretLinkView.as_view(), name='secret_link'),
    url(r'^file/$', views.FileView.as_view(), name='file'),

    url(r'^secret/$', views.SecretView.as_view(), name='secret'),
    url(r'^secret/(?P<secret_id>[^/]+)/$', views.SecretView.as_view(), name='secret'),

    url(r'^share/rights/(?P<share_id>[^/]+)/$', views.ShareRightsView.as_view(), name='share_rights'),

    url(r'^share/right/accept/$', views.ShareRightAcceptView.as_view(), name='share_right_accept'),
    url(r'^share/right/decline/$', views.ShareRightDeclineView.as_view(), name='share_right_decline'),
    url(r'^share/right/$', views.ShareRightView.as_view(), name='share_right'),
    url(r'^share/right/(?P<user_share_right_id>[^/]+)/$', views.ShareRightView.as_view(), name='share_right'),

    url(r'^share/link/$', views.ShareLinkView.as_view(), name='share_link'),

    url(r'^share/$', views.ShareView.as_view(), name='share'),
    url(r'^share/(?P<share_id>[^/]+)/$', views.ShareView.as_view(), name='share'),

    url(r'^group/$', views.GroupView.as_view(), name='group'),
    url(r'^group/rights/$', views.GroupRightsView.as_view(), name='group_rights'),
    url(r'^group/rights/(?P<group_id>[^/]+)/$', views.GroupRightsView.as_view(), name='group_rights'),
    url(r'^group/(?P<group_id>[^/]+)/$', views.GroupView.as_view(), name='group'),

    url(r'^membership/accept/$', views.MembershipAcceptView.as_view(), name='membership_accept'),
    url(r'^membership/decline/$', views.MembershipDeclineView.as_view(), name='membership_decline'),
    url(r'^membership/$', views.MembershipView.as_view(), name='membership'),

    # url(r'^$', views.api_root),

    url(r'^healthcheck/$', views.HealthCheckView.as_view(), name='healthcheck'),
    url(r'^info/$', views.InfoView.as_view(), name='info'),

]

if settings.DEBUG:
    # URLs for development purposes only
    urlpatterns += [
        url(r'^coverage/(?P<path>.*)$', django.views.static.serve,
            {'document_root':join(dirname(abspath(__file__)), '..', '..', 'htmlcov')}),
    ]