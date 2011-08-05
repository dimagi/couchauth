from django.contrib.auth import REDIRECT_FIELD_NAME
from couchauth.forms import AuthenticationForm
from django.contrib.auth.views import login as django_auth_login, logout, logout_then_login


def login(request, template_name='registration/login.html',
          redirect_field_name=REDIRECT_FIELD_NAME,
          authentication_form=AuthenticationForm):
    return django_auth_login(request, template_name, redirect_field_name, authentication_form)