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
    url(r'^owner/password/reset/$', views.PasswordResetView.as_view(),
        name='restapi_password_reset'),
    url(r'^owner/password/reset/confirm/$', views.PasswordResetConfirmView.as_view(),
        name='restapi_password_reset_confirm'),
    url(r'^owner/login/$', views.LoginView.as_view(), name='restapi_login'),
    # URLs that require a user to be logged in with a valid session / token.
    url(r'^owner/logout/$', views.LogoutView.as_view(), name='restapi_logout'),
    #url(r'^owner/user/$', views.UserDetailsView.as_view(), name='restapi_user_details'),
    url(r'^owner/password/change/$', views.PasswordChangeView.as_view(),
        name='restapi_password_change'),
    url(r'^owner/register/$', views.RegisterView.as_view(), name='restapi_register'),
    url(r'^owner/verify-email/$', views.VerifyEmailView.as_view(), name='restapi_verify_email'),

    # This url is used by django-allauth and empty TemplateView is
    # defined just to allow reverse() call inside app, for example when email
    # with verification link is being sent, then it's required to render email
    # content.

    # account_confirm_email - You should override this view to handle it in
    # your API client somehow and then, send post to /verify-email/ endpoint
    # with proper key.
    # If you don't want to use API on that step, then just use ConfirmEmailView
    # view from:
    # djang-allauth https://github.com/pennersr/django-allauth/blob/master/allauth/account/views.py#L190
    url(r'^owner/account-confirm-email/(?P<key>\w+)/$', TemplateView.as_view(),
        name='restapi_confirm_email'),
    # url(r'^$', views.api_root),
]