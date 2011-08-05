from couchdbkit.exceptions import ResourceNotFound
from couchdbkit.schema.properties import DateTimeProperty
from django.contrib.auth import models as django_auth_models
from django.contrib.auth import views as django_auth_views

from couchdbkit.ext.django.schema import Document, StringProperty, BooleanProperty, StringListProperty

class Email(object):
    def __get__(self, user, User):
        try:
            return user.emails[0]
        except IndexError:
            return None
    def __set__(self, user, value):
        while value in user.emails:
            user.emails.remove(value)
        user.emails.insert(0, value)

class User(Document):
    """
    Users within the Django authentication system are represented by this model.

    _id and password are required. Other fields are optional.
    """
    
    password = StringProperty() # Use '[algo]$[salt]$[hexdigest]'

    full_name = StringProperty()

    is_active = BooleanProperty(default=True)
    is_superuser = BooleanProperty(default=True)
    last_login = DateTimeProperty(required=False)
    date_joined = DateTimeProperty(required=False)

    emails = StringListProperty(required=True)

    email = Email()

    @property
    def username(self):
        return self.email

    @property
    def first_name(self):
        try:
            return self.full_name.split(' ')[0]
        except Exception:
            return ''

    @property
    def last_name(self):
        return self.full_name[self.full_name.index(' ')+1:]
    
    def get_full_name(self):
        return self.full_name

    @classmethod
    def get_one(cls, key):
        user = cls.view('couchauth/by_key', key=key, include_docs=True).one()
        if user is None:
            raise cls.DoesNotExist
        return user
    @property
    def id(self):
        return self._id

    class DoesNotExist(Exception):
        pass
    class MultipleExist(Exception):
        pass

    def is_anonymous(self):
        """
        Always returns False. This is a way of comparing User objects to
        anonymous users.
        """
        return False

    def is_authenticated(self):
        """
        Always return True. This is a way to tell if the user has been
        authenticated in templates.
        """
        return True

    def set_password(self, raw_password):
        if raw_password is None:
            self.set_unusable_password()
        else:
            import random
            algo = 'sha1'
            salt = django_auth_models.get_hexdigest(algo, str(random.random()), str(random.random()))[:5]
            hsh = django_auth_models.get_hexdigest(algo, salt, raw_password)
            self.password = '%s$%s$%s' % (algo, salt, hsh)

    def check_password(self, raw_password):
        """
        Returns a boolean of whether the raw_password was correct. Handles
        encryption formats behind the scenes.
        """
        # Backwards-compatibility check. Older passwords won't include the
        # algorithm or salt.
        if '$' not in self.password:
            is_correct = (self.password == django_auth_models.get_hexdigest('md5', '', raw_password))
            if is_correct:
                # Convert the password to the new, more secure format.
                self.set_password(raw_password)
                self.save()
            return is_correct
        return django_auth_models.check_password(raw_password, self.password)

    def set_unusable_password(self):
        # Sets a value that will never be a valid hash
        self.password = django_auth_models.UNUSABLE_PASSWORD

    def has_usable_password(self):
        if self.password is None \
            or self.password == django_auth_models.UNUSABLE_PASSWORD:
            return False
        else:
            return True

    def get_group_permissions(self, obj=None):
        """
        Returns a list of permission strings that this user has through
        his/her groups. This method queries all available auth backends.
        If an object is passed in, only permissions matching this object
        are returned.
        """
        permissions = set()
        for backend in django_auth.get_backends():
            if hasattr(backend, "get_group_permissions"):
                if obj is not None:
                    if backend.supports_object_permissions:
                        permissions.update(
                            backend.get_group_permissions(self, obj)
                        )
                else:
                    permissions.update(backend.get_group_permissions(self))
        return permissions

    def get_all_permissions(self, obj=None):
        return django_auth_models._user_get_all_permissions(self, obj)

    def has_perm(self, perm, obj=None):
        """
        Returns True if the user has the specified permission. This method
        queries all available auth backends, but returns immediately if any
        backend returns True. Thus, a user who has permission from a single
        auth backend is assumed to have permission in general. If an object
        is provided, permissions for this specific object are checked.
        """
        # Inactive users have no permissions.
        if not self.is_active:
            return False

        # Superusers have all permissions.
        if self.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return django_auth_models._user_has_perm(self, perm, obj)

    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has each of the specified permissions.
        If object is passed, it checks if the user has all required perms
        for this object.
        """
        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_module_perms(self, app_label):
        """
        Returns True if the user has any permissions in the given app
        label. Uses pretty much the same logic as has_perm, above.
        """
        if not self.is_active:
            return False

        if self.is_superuser:
            return True

        return django_auth_models._user_has_module_perms(self, app_label)

    def email_user(self, subject, message, from_email=None):
        "Sends an e-mail to this User."
        from django.core.mail import send_mail
        send_mail(subject, message, from_email, [self.email])