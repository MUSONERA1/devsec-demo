"""
Role-Based Access Control (RBAC) Module

This module provides decorators and utilities for enforcing role-based
authorization throughout the Django application. It uses Django's built-in
Group model to manage roles and provides a clean, auditable way to control
access to views and sensitive operations.

Security Principles:
    - Least privilege: Users get minimum necessary permissions
    - Fail secure: Default deny, explicit allow
    - Separation of concerns: Auth (who) vs Authz (what)
    - Auditable: All authorization decisions can be logged
    - Django-native: Uses built-in auth/groups system

See RBAC_DESIGN.md for comprehensive documentation.
"""

from functools import wraps
import logging
from django.core.exceptions import PermissionDenied
from django.contrib.auth.models import Group

logger = logging.getLogger(__name__)


def role_required(allowed_roles):
    """
    Decorator to enforce role-based access control on views.
    
    Raises PermissionDenied if:
        - User is not authenticated
        - User's groups do not contain any of the allowed roles
    
    Args:
        allowed_roles (str or list): Single role name or list of role names
        
    Returns:
        Decorator function
        
    Examples:
        @role_required("user")
        def dashboard_view(request):
            '''Only users with 'user' role can access.'''
            return render(request, 'dashboard.html')
        
        @role_required(["admin", "instructor"])
        def panel_view(request):
            '''Users must have admin OR instructor role.'''
            return render(request, 'panel.html')
    
    Security Notes:
        - This decorator MUST be applied to views requiring authorization
        - It checks request.user.groups, not individual permissions
        - PermissionDenied is caught by Django's 403 handler
        - All authorization checks are logged at WARNING level for audit
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]
    
    if not allowed_roles:
        raise ValueError("role_required requires at least one role name")

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Step 1: Authentication check
            if not request.user.is_authenticated:
                logger.warning(
                    f"Anonymous user attempted to access {request.path} "
                    f"(requires roles: {allowed_roles})"
                )
                raise PermissionDenied()

            # Step 2: Get user's current roles
            user_roles = list(request.user.groups.values_list("name", flat=True))
            
            # Step 3: Authorization check
            has_required_role = any(role in user_roles for role in allowed_roles)
            
            if has_required_role:
                logger.info(
                    f"User '{request.user.username}' authorized to access "
                    f"{request.path} (roles: {user_roles})"
                )
                return view_func(request, *args, **kwargs)
            
            # Step 4: Authorization denied
            logger.warning(
                f"User '{request.user.username}' denied access to {request.path} "
                f"(has roles: {user_roles}, requires: {allowed_roles})"
            )
            raise PermissionDenied()

        return wrapper
    
    return decorator


def admin_required(view_func):
    """
    Decorator to require admin role.
    
    Shorthand for @role_required("admin").
    
    Only users with the 'admin' group can access decorated views.
    
    Example:
        @admin_required
        def admin_dashboard(request):
            '''Only administrators can access.'''
            return render(request, 'admin_dashboard.html')
    
    Raises:
        PermissionDenied: If user is not authenticated or lacks 'admin' role
    """
    return role_required("admin")(view_func)


def has_role(user, role_name):
    """
    Check if a user has a specific role.
    
    Utility function for checking roles in views, templates, or other code.
    
    Args:
        user: Django User object
        role_name (str): Role to check
        
    Returns:
        bool: True if user has the role, False otherwise
        
    Example:
        if has_role(request.user, 'admin'):
            # Admin-specific logic
            pass
    
    Security Notes:
        - Safe to call with anonymous users (returns False)
        - Should be supplemented with @role_required decorator on views
        - Useful for conditional logic, not primary authorization
    """
    if not user.is_authenticated:
        return False
    return user.groups.filter(name=role_name).exists()


def has_any_role(user, role_names):
    """
    Check if user has any of the specified roles.
    
    Args:
        user: Django User object
        role_names (list): List of role names to check
        
    Returns:
        bool: True if user has at least one of the roles
        
    Example:
        if has_any_role(request.user, ['admin', 'instructor']):
            # Staff-specific logic
            pass
    """
    if not user.is_authenticated:
        return False
    return user.groups.filter(name__in=role_names).exists()


def has_all_roles(user, role_names):
    """
    Check if user has ALL of the specified roles.
    
    Args:
        user: Django User object
        role_names (list): List of role names to check
        
    Returns:
        bool: True if user has all specified roles
        
    Example:
        if has_all_roles(request.user, ['user', 'verified']):
            # User is both authenticated and verified
            pass
    """
    if not user.is_authenticated:
        return False
    user_role_count = user.groups.filter(name__in=role_names).count()
    return user_role_count == len(role_names)


def get_user_roles(user):
    """
    Get all roles for a user.
    
    Args:
        user: Django User object
        
    Returns:
        list: List of role names (group names) for the user
        
    Example:
        roles = get_user_roles(request.user)
        print(f"User has roles: {', '.join(roles)}")
    """
    if not user.is_authenticated:
        return []
    return list(user.groups.values_list("name", flat=True))