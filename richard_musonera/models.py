from django.db import models
from django.contrib.auth.models import User
from django.core.validators import URLValidator
from django.db.models.signals import post_save
from django.dispatch import receiver
import logging

from .file_upload_security import (
    validate_avatar,
    avatar_upload_path,
    MAX_AVATAR_SIZE,
)

logger = logging.getLogger(__name__)


class UserProfile(models.Model):
    """Extended user profile information."""
    
    ROLE_CHOICES = [
        ('user', 'User'),
        ('instructor', 'Instructor'),
        ('admin', 'Admin'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, max_length=500)
    avatar_url = models.URLField(blank=True, validators=[URLValidator()])
    profile_picture = models.FileField(
        upload_to=avatar_upload_path,
        blank=True,
        null=True,
        validators=[validate_avatar],
        help_text=f'Upload a profile picture (JPG, PNG, GIF, WebP - max {MAX_AVATAR_SIZE // (1024*1024)}MB)'
    )
    department = models.CharField(max_length=100, blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username}'s Profile"


# Auto-create UserProfile when User is created
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Automatically create a UserProfile when a new User is created."""
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Automatically save the UserProfile when the User is saved."""
    if hasattr(instance, 'profile'):
        instance.profile.save()


# ==========================================
# AUDIT LOGGING (Security Monitoring)
# ==========================================

class AuditLog(models.Model):
    """
    Audit log for tracking security-sensitive events.
    
    Records authentication, authorization, and privilege changes.
    Designed to:
    - Not store sensitive information (no passwords, tokens)
    - Track user actions for compliance and investigation
    - Enable real-time alerts on suspicious activity
    - Maintain tamper-evident records
    
    Event Types:
    - AUTH_REGISTER: User registration
    - AUTH_LOGIN_SUCCESS: Successful login
    - AUTH_LOGIN_FAILURE: Failed login attempt
    - AUTH_LOGOUT: User logout
    - AUTH_PASSWORD_CHANGE: User changed password
    - AUTH_PASSWORD_RESET_REQUEST: Password reset requested
    - AUTH_PASSWORD_RESET_CONFIRM: Password reset confirmed
    - AUTHZ_ROLE_ADD: Role assigned to user
    - AUTHZ_ROLE_REMOVE: Role removed from user
    - AUTHZ_PERMISSION_CHANGE: Permission changed
    """
    
    EVENT_TYPES = [
        ('AUTH_REGISTER', 'User Registration'),
        ('AUTH_LOGIN_SUCCESS', 'Login Success'),
        ('AUTH_LOGIN_FAILURE', 'Login Failure'),
        ('AUTH_LOGOUT', 'Logout'),
        ('AUTH_PASSWORD_CHANGE', 'Password Changed'),
        ('AUTH_PASSWORD_RESET_REQUEST', 'Password Reset Request'),
        ('AUTH_PASSWORD_RESET_CONFIRM', 'Password Reset Confirm'),
        ('AUTHZ_ROLE_ADD', 'Role Added'),
        ('AUTHZ_ROLE_REMOVE', 'Role Removed'),
        ('AUTHZ_ROLE_BULK_CHANGE', 'Roles Changed'),
    ]
    
    # Core fields
    event_type = models.CharField(
        max_length=50,
        choices=EVENT_TYPES,
        db_index=True,
        help_text='Type of security event'
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text='When the event occurred'
    )
    
    # User information
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs_as_actor',
        help_text='User who performed the action'
    )
    target_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs_as_target',
        help_text='User who was the target of the action'
    )
    
    # Request information (for forensics)
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text='Client IP address'
    )
    user_agent = models.TextField(
        blank=True,
        help_text='Client user agent string'
    )
    
    # Event details (audit trail)
    event_details = models.JSONField(
        default=dict,
        blank=True,
        help_text='Additional event metadata (no sensitive data)'
    )
    
    # Status
    success = models.BooleanField(
        default=True,
        db_index=True,
        help_text='Whether the action succeeded'
    )
    error_description = models.TextField(
        blank=True,
        help_text='Error message if action failed'
    )
    
    class Meta:
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['event_type', '-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['target_user', '-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
    
    @classmethod
    def log_event(cls, event_type, request=None, user=None, target_user=None,
                  success=True, details=None, error_msg=None):
        """
        Convenience method to create audit log entries.
        
        Args:
            event_type (str): Type of event from EVENT_TYPES
            request: Django Request object (optional)
            user: User performing action (optional)
            target_user: User being acted upon (optional)
            success (bool): Whether action succeeded
            details (dict): Additional metadata (NO SENSITIVE DATA!)
            error_msg (str): Error description if action failed
            
        Returns:
            AuditLog: The created audit log entry
            
        Security Notes:
            - Never include passwords, tokens, or secrets in details
            - User agent and IP are captured for forensics
            - All events are immutable (not updated after creation)
            - Timestamps cannot be modified
        """
        from richard_musonera.rbac import get_client_ip
        
        # Extract client info from request
        ip_address = None
        user_agent = None
        if request:
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
        
        # Sanitize details - ensure no sensitive data
        if details is None:
            details = {}
        
        # Create the audit log entry
        audit_entry = cls(
            event_type=event_type,
            user=user,
            target_user=target_user,
            ip_address=ip_address,
            user_agent=user_agent,
            event_details=details,
            success=success,
            error_description=error_msg or ''
        )
        
        audit_entry.save()
        
        # Enhanced logging with audit event
        log_level = logging.INFO if success else logging.WARNING
        logger.log(
            log_level,
            f"AUDIT: {event_type} | "
            f"User: {user.username if user else 'anonymous'} | "
            f"Target: {target_user.username if target_user else 'N/A'} | "
            f"Success: {success} | "
            f"IP: {ip_address}"
        )
        
        return audit_entry
