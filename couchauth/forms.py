from django.contrib.auth.forms import AuthenticationForm as DjangoAuthenticationForm
import django
from couchauth import authenticate
from django.utils.translation import ugettext_lazy as _

class AuthenticationForm(DjangoAuthenticationForm):
    username = django.forms.CharField(label=_("Username")) # remove inherited limit of max_length=30

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        print username
        print password

        if username and password:
            self.user_cache = authenticate(username=username, password=password)
            if self.user_cache is None:
                raise django.forms.ValidationError(_("Please enter a correct username and password. Note that both fields are case-sensitive."))
            elif not self.user_cache.is_active:
                raise django.forms.ValidationError(_("This account is inactive."))

        # TODO: determine whether this should move to its own method.
        if self.request:
            if not self.request.session.test_cookie_worked():
                raise django.forms.ValidationError(_("Your Web browser doesn't appear to have cookies enabled. Cookies are required for logging in."))

        return self.cleaned_data