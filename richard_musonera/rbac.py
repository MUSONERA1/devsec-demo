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


# ==========================================
# OBJECT-LEVEL ACCESS CONTROL (IDOR Prevention)
# ==========================================

def check_object_ownership(user, obj, owner_field="user"):
    """
    Check if a user owns an object (IDOR Prevention).
    
    Raises PermissionDenied if the user doesn't own the object.
    
    Args:
        user: Django User object (request.user)
        obj: Object to check ownership of
        owner_field (str): Name of the field containing the owner
        
    Raises:
        PermissionDenied: If user is not authenticated or does not own the object
        
    Example:
        profile = UserProfile.objects.get(pk=profile_id)
        check_object_ownership(request.user, profile)  # Raises if not owner
        # Continue processing profile...
    
    Security Notes:
        - This prevents IDOR (Insecure Direct Object Reference)
        - Always check before allowing access to user-owned objects
        - Works with any object that has an owner field
        - Logs all denied access attempts for audit
    """
    if not user.is_authenticated:
        logger.warning(
            f"Anonymous user attempted to access object owned by another user"
        )
        raise PermissionDenied("Authentication required")

    # Get the owner from the object
    try:
        owner = getattr(obj, owner_field)
    except AttributeError:
        logger.error(
            f"Object {obj.__class__.__name__} does not have field '{owner_field}'"
        )
        raise PermissionDenied("Invalid object ownership check")

    # Check ownership
    if owner != user:
        logger.warning(
            f"User '{user.username}' (id={user.id}) attempted unauthorized access "
            f"to {obj.__class__.__name__} owned by user id={owner.id}"
        )
        raise PermissionDenied("You do not have permission to access this resource")

    logger.info(
        f"User '{user.username}' authorized to access owned "
        f"{obj.__class__.__name__} object"
    )


def get_user_owned_object(user, model, pk, owner_field="user"):
    """
    Safely retrieve a user-owned object, checking ownership first.
    
    Returns None if object doesn't exist or user doesn't own it.
    Raises PermissionDenied if ownership check fails.
    
    Args:
        user: Django User object (request.user)
        model: Django model class
        pk: Primary key of object to retrieve
        owner_field (str): Name of the owner field
        
    Returns:
        Object if user owns it, None if it doesn't exist
        
    Raises:
        PermissionDenied: If user doesn't own the object
        
    Example:
        # In a view
        try:
            profile = get_user_owned_object(
                request.user, 
                UserProfile, 
                profile_id
            )
            # Use profile...
        except UserProfile.DoesNotExist:
            return HttpNotFound()
    
    Security Notes:
        - Prevents IDOR by verifying ownership before returning object
        - Returns None for standard 404 handling
        - Logs unauthorized access attempts
    """
    if not user.is_authenticated:
        raise PermissionDenied("Authentication required")

    try:
        obj = model.objects.get(pk=pk)
    except model.DoesNotExist:
        return None

    check_object_ownership(user, obj, owner_field)
    return obj


def owner_required(owner_field="user"):
    """
    Decorator to enforce object ownership for views.
    
    The decorated view function must accept an 'object_id' or 'pk' parameter.
    
    Args:
        owner_field (str): Name of the owner field in the model
        
    Example:
        @owner_required()
        @login_required
        def edit_profile(request, pk):
            profile = UserProfile.objects.get(pk=pk)
            # check_object_ownership is already verified by decorator
            form = UserProfileForm(request.POST, instance=profile)
            ...
    
    Security Notes:
        - Must be combined with @login_required or @role_required
        - Prevents IDOR by checking ownership before view executes
        - Works on views that accept 'pk' or 'object_id' URL parameter
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Get the primary key from kwargs
            pk = kwargs.get('pk') or kwargs.get('object_id') or kwargs.get('user_id')
            
            if not pk:
                logger.error(
                    f"@owner_required decorator applied to view without pk/object_id/user_id parameter"
                )
                raise PermissionDenied("Missing object identifier")

            if not request.user.is_authenticated:
                raise PermissionDenied("Authentication required")

            # Verify the user owns the object
            # For profiles linked to users, we can check directly
            from django.contrib.auth.models import User
            try:
                target_user = User.objects.get(pk=pk)
                if target_user != request.user and not has_role(request.user, 'admin'):
                    logger.warning(
                        f"User '{request.user.username}' (id={request.user.id}) "
                        f"attempted unauthorized access to user id={pk}"
                    )
                    raise PermissionDenied("You do not have permission to access this resource")
            except User.DoesNotExist:
                return view_func(request, *args, **kwargs)  # Let view handle 404

            return view_func(request, *args, **kwargs)

        return wrapper
    return decorator


# ==========================================
# BRUTE-FORCE PROTECTION (Task #36)
# ==========================================

def get_client_ip(request):
    """
    Extract client IP address from request.
    
    Handles:
    - Direct connection IP
    - X-Forwarded-For header (proxies)
    - X-Real-IP header (nginx)
    
    Args:
        request: Django request object
        
    Returns:
        str: Client IP address
        
    Security Notes:
        - X-Forwarded-For can be spoofed in untrusted networks
        - This is best-effort for rate limiting purposes only
        - Real protection should include request validation
    """
    # Check for proxy headers
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first
        ip = x_forwarded_for.split(',')[0].strip()
        return ip
    
    # Check X-Real-IP header (nginx)
    x_real_ip = request.META.get('HTTP_X_REAL_IP')
    if x_real_ip:
        return x_real_ip
    
    # Fall back to direct connection IP
    return request.META.get('REMOTE_ADDR', 'unknown')


def track_failed_login(request, username):
    """
    Record a failed login attempt.
    
    Uses Django's cache to track failed attempts per IP address.
    After MAX_LOGIN_ATTEMPTS failures within LOCKOUT_PERIOD,
    the IP is temporarily locked out.
    
    Args:
        request: Django request object
        username: Username that failed to authenticate
        
    Returns:
        dict: {'locked_out': bool, 'attempts': int, 'remaining': int}
        
    Security Configuration:
        - MAX_LOGIN_ATTEMPTS: 5 failures (default)
        - LOCKOUT_PERIOD: 900 seconds = 15 minutes (default)
        - Tracks by IP address, not username (prevents enumeration)
    
    Example:
        result = track_failed_login(request, username)
        if result['locked_out']:
            messages.error(request, f"Too many failed attempts. Try again in 15 minutes.")
        else:
            messages.error(request, f"Invalid credentials ({result['remaining']} tries left)")
    
    Audit Notes:
        - Failed attempts are logged with IP and timestamp
        - System prevents attacker enumeration by not disclosing failed username
        - Legitimate users can retry after lockout period expires
    """
    from django.core.cache import cache
    from django.conf import settings
    
    # Get configuration
    MAX_LOGIN_ATTEMPTS = getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
    LOCKOUT_PERIOD = getattr(settings, 'LOCKOUT_PERIOD', 900)  # 15 minutes
    
    # Get client IP
    client_ip = get_client_ip(request)
    
    # Create cache key for this IP
    cache_key = f"login_attempts_{client_ip}"
    lockout_key = f"login_locked_{client_ip}"
    
    # Check if already locked out
    if cache.get(lockout_key):
        logger.warning(
            f"Login attempt from locked-out IP: {client_ip}, username: {username}"
        )
        return {
            'locked_out': True,
            'attempts': MAX_LOGIN_ATTEMPTS,
            'remaining': 0
        }
    
    # Increment failed attempt counter
    attempts = cache.get(cache_key, 0)
    attempts += 1
    cache.set(cache_key, attempts, LOCKOUT_PERIOD)
    
    # Log the attempt
    logger.warning(
        f"Failed login attempt #{attempts} from IP {client_ip}, "
        f"username: {username}"
    )
    
    # Check if we've exceeded the limit
    if attempts >= MAX_LOGIN_ATTEMPTS:
        cache.set(lockout_key, True, LOCKOUT_PERIOD)
        logger.warning(
            f"IP {client_ip} locked out after {attempts} failed login attempts"
        )
        return {
            'locked_out': True,
            'attempts': attempts,
            'remaining': 0
        }
    
    return {
        'locked_out': False,
        'attempts': attempts,
        'remaining': MAX_LOGIN_ATTEMPTS - attempts
    }


def is_login_locked(request):
    """
    Check if a client IP is currently locked out from login.
    
    Args:
        request: Django request object
        
    Returns:
        bool: True if locked out, False otherwise
        
    Example:
        if is_login_locked(request):
            return render(request, 'login.html', {
                'locked_out': True,
                'message': 'Too many failed attempts. Please try again later.'
            })
    
    Security Notes:
        - Check this BEFORE attempting authentication
        - Prevents expensive password hash comparisons during brute-force
        - Lockout is time-based and automatically expires
    """
    from django.core.cache import cache
    
    client_ip = get_client_ip(request)
    lockout_key = f"login_locked_{client_ip}"
    
    is_locked = cache.get(lockout_key, False)
    
    if is_locked:
        logger.info(
            f"Login attempt blocked due to lockout: IP {client_ip}"
        )
    
    return is_locked


def reset_login_attempts(request, username):
    """
    Clear failed login attempts and lockout flag for a client IP after successful login.
    
    Args:
        request: Django request object
        username: Username that successfully authenticated
        
    Example:
        user = authenticate(request, username=username, password=password)
        if user is not None:
            reset_login_attempts(request, username)
            login(request, user)
    
    Security Notes:
        - Call AFTER successful authentication
        - Clears both attempt counter and lockout flag for this IP
        - Allows legitimate users to recover if they had a brief brute-force period
        - Prevents permanent lockout for valid users
    """
    from django.core.cache import cache
    
    client_ip = get_client_ip(request)
    cache_key = f"login_attempts_{client_ip}"
    lockout_key = f"login_locked_{client_ip}"
    
    # Clear both attempt counter and lockout flag
    cache.delete(cache_key)
    cache.delete(lockout_key)
    
    logger.info(
        f"Login attempts and lockout cleared for IP {client_ip}, username: {username}"
    )


# ==========================================
# SAFE REDIRECT HANDLING (Task #38)
# ==========================================

def is_safe_redirect_url(url, allowed_hosts=None):
    """
    Validate if a redirect URL is safe (internal only, no external redirects).
    
    Prevents open redirect vulnerabilities by ensuring redirects only go to
    internal URLs within the same domain.
    
    Args:
        url (str): URL to validate
        allowed_hosts (list): List of allowed hosts (defaults to Django's ALLOWED_HOSTS)
        
    Returns:
        bool: True if URL is safe to redirect to, False otherwise
        
    Safe URL Examples:
        - /dashboard/
        - /profile/
        - /admin/users/
        
    Unsafe URL Examples:
        - https://example.com/
        - //evil.com/phishing
        - javascript:alert('xss')
        - data:text/html,<script>
        
    Security Notes:
        - Only allows relative URLs (starting with /) or URLs on allowed hosts
        - Rejects protocol-relative URLs (//) which can bypass host checks
        - Rejects javascript: and data: URLs
        - Uses Django's built-in URL validation
        
    Examples:
        # In a view
        next_url = request.GET.get('next')
        if is_safe_redirect_url(next_url):
            return redirect(next_url)
        return redirect('dashboard')
    """
    from django.utils.http import url_has_allowed_host_and_scheme
    from django.conf import settings
    
    if not url:
        return False
    
    # Strip whitespace
    url = url.strip()
    
    # Reject empty strings
    if not url:
        return False
    
    # Reject javascript: and data: URIs (XSS prevention)
    if url.lower().startswith(('javascript:', 'data:', 'vbscript:')):
        logger.warning(f"Rejected redirect to potentially dangerous protocol: {url[:50]}")
        return False
    
    # Reject protocol-relative URLs (//) which can bypass host checks
    if url.startswith('//'):
        logger.warning(f"Rejected protocol-relative redirect URL: {url[:50]}")
        return False
    
    # Allow relative URLs (starting with /)
    if url.startswith('/'):
        return True
    
    # For absolute URLs, use Django's built-in URL validation
    if allowed_hosts is None:
        allowed_hosts = settings.ALLOWED_HOSTS
    
    # Django's url_has_allowed_host_and_scheme checks:
    # - URL host is in ALLOWED_HOSTS
    # - URL uses http/https scheme only
    is_safe = url_has_allowed_host_and_scheme(
        url,
        allowed_hosts=allowed_hosts,
        require_https=settings.SECURE_SSL_REDIRECT or not settings.DEBUG
    )
    
    if not is_safe:
        logger.warning(
            f"Rejected redirect to external URL: {url[:100]}"
        )
    
    return is_safe


def get_safe_redirect(url, fallback_url='dashboard', allowed_hosts=None):
    """
    Get a validated redirect URL, falling back to a safe default.
    
    Convenience function to validate and redirect with a safe fallback.
    
    Args:
        url (str): URL to redirect to
        fallback_url (str): Safe URL to redirect to if url is invalid (URL name or path)
        allowed_hosts (list): List of allowed hosts for validation
        
    Returns:
        str: Safe redirect URL (either the validated url or fallback_url)
        
    Examples:
        # In a view
        next_url = request.GET.get('next', 'dashboard')
        safe_url = get_safe_redirect(next_url, fallback_url='dashboard')
        return redirect(safe_url)
        
        # With URL name
        safe_url = get_safe_redirect(request.POST.get('return_to'), 'profile')
        return redirect(safe_url)
    
    Security Notes:
        - Always provide a safe fallback_url
        - fallback_url should be a URL name (e.g. 'dashboard') or safe path
        - Never trust user input for redirects without validation
    """
    if is_safe_redirect_url(url, allowed_hosts):
        return url
    
    # Safe handling of None values - convert to string safely
    url_str = str(url) if url else ''
    logger.warning(
        f"Using fallback redirect '{fallback_url}' for unsafe URL: {url_str[:100]}"
    )
    return fallback_url


# ==========================================
# AUDIT LOGGING UTILITIES
# ==========================================

def audit_log_auth_register(request, user, success=True, error_msg=None):
    """
    Log user registration event.
    
    Args:
        request: Django request object
        user: User who registered
        success (bool): Whether registration succeeded
        error_msg (str): Error description if failed
    """
    from richard_musonera.models import AuditLog
    
    AuditLog.log_event(
        event_type='AUTH_REGISTER',
        request=request,
        user=user,
        target_user=user,
        success=success,
        details={'username': user.username if user else 'N/A'},
        error_msg=error_msg
    )


def audit_log_auth_login(request, username, success=True, error_msg=None):
    """
    Log login attempt event.
    
    Args:
        request: Django request object
        username (str): Username for login attempt
        success (bool): Whether login succeeded
        error_msg (str): Error description if failed
    """
    from django.contrib.auth.models import User
    from richard_musonera.models import AuditLog
    
    event_type = 'AUTH_LOGIN_SUCCESS' if success else 'AUTH_LOGIN_FAILURE'
    
    # Get user if login was successful
    user = None
    if success:
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
    
    # Log only the username, not the related query
    AuditLog.log_event(
        event_type=event_type,
        request=request,
        user=user,
        target_user=user,
        success=success,
        details={'username': username},
        error_msg=error_msg
    )


def audit_log_auth_logout(request, user):
    """
    Log logout event.
    
    Args:
        request: Django request object
        user: User who logged out
    """
    from richard_musonera.models import AuditLog
    
    AuditLog.log_event(
        event_type='AUTH_LOGOUT',
        request=request,
        user=user,
        target_user=user,
        success=True,
        details={'username': user.username}
    )


def audit_log_password_change(request, user, success=True, error_msg=None):
    """
    Log password change event.
    
    Args:
        request: Django request object
        user: User who changed password
        success (bool): Whether change succeeded
        error_msg (str): Error description if failed
    """
    from richard_musonera.models import AuditLog
    
    AuditLog.log_event(
        event_type='AUTH_PASSWORD_CHANGE',
        request=request,
        user=user,
        target_user=user,
        success=success,
        details={'username': user.username},
        error_msg=error_msg
    )


def audit_log_password_reset_request(request, username, success=True):
    """
    Log password reset request.
    
    Args:
        request: Django request object
        username (str): Username requesting reset
        success (bool): Whether email was sent
    """
    from richard_musonera.models import AuditLog
    
    AuditLog.log_event(
        event_type='AUTH_PASSWORD_RESET_REQUEST',
        request=request,
        user=None,
        target_user=None,
        success=success,
        details={'username_requested': username}
    )


def audit_log_password_reset_confirm(request, user, success=True, error_msg=None):
    """
    Log password reset confirmation (actual password change).
    
    Args:
        request: Django request object
        user: User who confirmed password reset
        success (bool): Whether reset succeeded
        error_msg (str): Error description if failed
    """
    from richard_musonera.models import AuditLog
    
    AuditLog.log_event(
        event_type='AUTH_PASSWORD_RESET_CONFIRM',
        request=request,
        user=user,
        target_user=user,
        success=success,
        details={'username': user.username},
        error_msg=error_msg
    )


def audit_log_role_change(request, admin_user, target_user, role_name, action, success=True, error_msg=None):
    """
    Log role assignment or removal.
    
    Args:
        request: Django request object
        admin_user: User performing the action (admin)
        target_user: User whose role is being changed
        role_name (str): Role name being added/removed
        action (str): 'add' or 'remove'
        success (bool): Whether action succeeded
        error_msg (str): Error description if failed
    """
    from richard_musonera.models import AuditLog
    
    event_type = 'AUTHZ_ROLE_ADD' if action == 'add' else 'AUTHZ_ROLE_REMOVE'
    
    AuditLog.log_event(
        event_type=event_type,
        request=request,
        user=admin_user,
        target_user=target_user,
        success=success,
        details={
            'admin': admin_user.username if admin_user else 'system',
            'target_user': target_user.username,
            'role': role_name,
            'action': action
        },
        error_msg=error_msg
    )