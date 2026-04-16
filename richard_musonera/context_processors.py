"""
Template context processors for RBAC.

This module provides context processors that make role information available
in all templates, enabling template-level access control hints and UI elements.

Usage in templates:
    {% if user_roles.admin %}
        <a href="{% url 'admin_panel' %}">Admin Panel</a>
    {% endif %}
    
    {% if 'instructor' in user_roles %}
        <!-- Show instructor-only content -->
    {% endif %}
"""

from .rbac import get_user_roles, has_role


def user_roles_context(request):
    """
    Add user roles to template context.
    
    Makes available:
        - user_roles: Comma-separated string of role names
        - user_role_dict: Dictionary for role.name syntax
        - is_admin: Boolean for admin role
        - is_instructor: Boolean for instructor role
        - is_user: Boolean for user role
    
    Add to TEMPLATES context_processors in settings:
        'richard_musonera.context_processors.user_roles_context'
    """
    user = request.user
    
    if not user.is_authenticated:
        return {
            'user_roles': [],
            'user_role_dict': {},
            'is_admin': False,
            'is_instructor': False,
            'is_user': False,
        }
    
    roles = get_user_roles(user)
    role_dict = {role: True for role in roles}
    
    return {
        'user_roles': roles,
        'user_role_dict': role_dict,
        'is_admin': has_role(user, 'admin'),
        'is_instructor': has_role(user, 'instructor'),
        'is_user': has_role(user, 'user'),
    }
