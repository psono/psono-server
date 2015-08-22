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
from django.conf.urls import patterns, url, include
import views
from django.views.generic import TemplateView

urlpatterns = [
    # URLs that do not require a session or valid token
    #url(r'^authentication/authkey/reset/$', views.AuthkeyResetView.as_view(),
    #    name='authentication_authkey_reset'),
    #url(r'^authentication/authkey/reset/confirm/$', views.AuthkeyResetConfirmView.as_view(),
    #    name='authentication_authkey_reset_confirm'),

    url(r'^authentication/login/$', views.LoginView.as_view(), name='authentication_login'),
    url(r'^authentication/register/$', views.RegisterView.as_view(), name='authentication_register'),
    url(r'^authentication/verify-email/$', views.VerifyEmailView.as_view(), name='authentication_verify_email'),
    url(r'^authentication/confirm-email/(?P<key>\w+)/$', TemplateView.as_view(),
        name='authentication_confirm_email'),

    # URLs that require a user to be logged in with a valid session / token.
    url(r'^authentication/logout/$', views.LogoutView.as_view(), name='authentication_logout'),
    #url(r'^owner/user/$', views.UserDetailsView.as_view(), name='authentication_user_details'),
    url(r'^authentication/authkey/change/$', views.AuthkeyChangeView.as_view(),
        name='authentication_authkey_change'),
    # url(r'^$', views.api_root),
]