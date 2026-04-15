from functools import wraps
from django.core.exceptions import PermissionDenied

def role_required(allowed_roles):
    """
    Decorator to check if user has required role(s).
    
    Usage:
        @role_required("user")
        def my_view(request): ...
        
        @role_required(["admin", "instructor"])
        def my_view(request): ...
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):

            if not request.user.is_authenticated:
                raise PermissionDenied()

            user_roles = list(request.user.groups.values_list("name", flat=True))

            if any(role in user_roles for role in allowed_roles):
                return view_func(request, *args, **kwargs)

            raise PermissionDenied()

        return wrapper
    return decorator


def admin_required(view_func):
    """
    Decorator to require admin role. Shorthand for @role_required("admin")
    """
    return role_required("admin")(view_func)