from functools import wraps
from flask_login import current_user
from flask import abort

# Admin Decorator
def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # If the current user is not authenticated or the current user is not the admin, return a 403 error
        if current_user.is_authenticated and current_user.id == 1:
            return func(*args, **kwargs)
        return abort(403)
    return decorated_function
