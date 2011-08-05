from couchauth.models import User

class CouchAuthBackend(object):
    """
    Authenticates against couchauth.models.User.
    """
    supports_object_permissions = False
    supports_anonymous_user = True

    # TODO: Model, login attribute name and password attribute name should be
    # configurable.
    def authenticate(self, username=None, password=None):
        try:
            user = User.get_one(username)
            if user.check_password(password):
                return user
        except User.DoesNotExist, User.MultipleExist:
            return None

    def get_user(self, user_id):
        return User.get(user_id)