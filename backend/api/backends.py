from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class EmailBackend(ModelBackend):
    """
    Custom authentication backend.

    Allows users to sign in using their email address.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            # Check if a user with the given email exists.
            user = UserModel.objects.get(email=username)
        except UserModel.DoesNotExist:
            # If no user is found, authentication fails.
            return None
        
        # Check if the provided password is correct for that user.
        if user.check_password(password):
            return user # Authentication successful
        
        return None # Password was incorrect

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None