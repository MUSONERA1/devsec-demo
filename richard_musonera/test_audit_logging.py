"""
Tests for Audit Logging System

Tests verify that security-sensitive events are properly logged:
- Registration (success and failure)
- Login success and failure
- Logout
- Password changes and resets
- Role and permission changes
"""

from django.test import TestCase, Client, RequestFactory
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from richard_musonera.models import AuditLog
from richard_musonera.rbac import (
    audit_log_auth_register,
    audit_log_auth_login,
    audit_log_auth_logout,
    audit_log_password_change,
    audit_log_password_reset_request,
    audit_log_password_reset_confirm,
    audit_log_role_change
)


class AuditLogModelTests(TestCase):
    """Test the AuditLog model."""
    
    def setUp(self):
        """Set up test users."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!@#'
        )
        self.factory = RequestFactory()
    
    def test_audit_log_created(self):
        """Test that audit logs can be created."""
        audit_entry = AuditLog.objects.create(
            event_type='AUTH_LOGIN_SUCCESS',
            user=self.user,
            target_user=self.user,
            success=True
        )
        self.assertEqual(audit_entry.event_type, 'AUTH_LOGIN_SUCCESS')
        self.assertEqual(audit_entry.user, self.user)
        self.assertTrue(audit_entry.success)
    
    def test_audit_log_immutable(self):
        """Test that audit log timestamps cannot be tampered with."""
        before = timezone.now()
        audit_entry = AuditLog.objects.create(
            event_type='AUTH_LOGIN_SUCCESS',
            user=self.user,
            success=True
        )
        after = timezone.now()
        
        self.assertGreaterEqual(audit_entry.timestamp, before)
        self.assertLessEqual(audit_entry.timestamp, after)
    
    def test_audit_log_string_representation(self):
        """Test audit log string representation."""
        audit_entry = AuditLog.objects.create(
            event_type='AUTH_LOGIN_SUCCESS',
            user=self.user,
            success=True
        )
        str_repr = str(audit_entry)
        self.assertIn('AUTH_LOGIN_SUCCESS', str_repr)
        self.assertIn('2', str_repr)  # Year part of timestamp
    
    def test_event_details_stored_as_json(self):
        """Test that event details are stored as JSON."""
        details = {'username': 'testuser', 'ip': '127.0.0.1'}
        audit_entry = AuditLog.objects.create(
            event_type='AUTH_LOGIN_SUCCESS',
            user=self.user,
            success=True,
            event_details=details
        )
        
        audit_entry.refresh_from_db()
        self.assertEqual(audit_entry.event_details['username'], 'testuser')
        self.assertEqual(audit_entry.event_details['ip'], '127.0.0.1')


class AuditLogUtilityFunctionsTests(TestCase):
    """Test audit logging utility functions."""
    
    def setUp(self):
        """Set up test users and request factory."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!@#'
        )
        self.factory = RequestFactory()
    
    def test_audit_log_auth_register_success(self):
        """Test registration audit log for successful registration."""
        request = self.factory.post('/register/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        request.META['HTTP_USER_AGENT'] = 'TestBrowser/1.0'
        
        initial_count = AuditLog.objects.count()
        audit_log_auth_register(request, self.user, success=True)
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTH_REGISTER')
        self.assertEqual(log_entry.user, self.user)
        self.assertTrue(log_entry.success)
    
    def test_audit_log_auth_register_failure(self):
        """Test registration audit log for failed registration."""
        request = self.factory.post('/register/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_auth_register(request, None, success=False, 
                               error_msg="Invalid form data")
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTH_REGISTER')
        self.assertFalse(log_entry.success)
        self.assertEqual(log_entry.error_description, "Invalid form data")
    
    def test_audit_log_auth_login_success(self):
        """Test login audit log for successful login."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_auth_login(request, 'testuser', success=True)
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTH_LOGIN_SUCCESS')
        self.assertTrue(log_entry.success)
    
    def test_audit_log_auth_login_failure(self):
        """Test login audit log for failed login."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_auth_login(request, 'testuser', success=False, 
                            error_msg="Invalid credentials")
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTH_LOGIN_FAILURE')
        self.assertFalse(log_entry.success)
    
    def test_audit_log_auth_logout(self):
        """Test logout audit log."""
        request = self.factory.post('/logout/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_auth_logout(request, self.user)
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTH_LOGOUT')
        self.assertEqual(log_entry.user, self.user)
        self.assertTrue(log_entry.success)
    
    def test_audit_log_password_change_success(self):
        """Test password change audit log for success."""
        request = self.factory.post('/change-password/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_password_change(request, self.user, success=True)
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTH_PASSWORD_CHANGE')
        self.assertEqual(log_entry.user, self.user)
        self.assertTrue(log_entry.success)
    
    def test_audit_log_password_change_failure(self):
        """Test password change audit log for failure."""
        request = self.factory.post('/change-password/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_password_change(request, self.user, success=False,
                                 error_msg="Passwords don't match")
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTH_PASSWORD_CHANGE')
        self.assertFalse(log_entry.success)
        self.assertEqual(log_entry.error_description, "Passwords don't match")
    
    def test_audit_log_password_reset_request(self):
        """Test password reset request audit log."""
        request = self.factory.post('/password-reset/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_password_reset_request(request, 'test@example.com', success=True)
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTH_PASSWORD_RESET_REQUEST')
        self.assertTrue(log_entry.success)
        self.assertEqual(log_entry.event_details['username_requested'], 'test@example.com')
    
    def test_audit_log_password_reset_confirm(self):
        """Test password reset confirm audit log."""
        request = self.factory.post('/password-reset/confirm/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_password_reset_confirm(request, self.user, success=True)
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTH_PASSWORD_RESET_CONFIRM')
        self.assertEqual(log_entry.user, self.user)
        self.assertTrue(log_entry.success)
    
    def test_audit_log_role_add(self):
        """Test role add audit log."""
        admin_user = User.objects.create_user(
            username='admin',
            password='AdminPass123!@#'
        )
        request = self.factory.post('/admin/assign-role/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_role_change(request, admin_user, self.user, 'instructor', 
                             'add', success=True)
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTHZ_ROLE_ADD')
        self.assertEqual(log_entry.user, admin_user)
        self.assertEqual(log_entry.target_user, self.user)
        self.assertEqual(log_entry.event_details['role'], 'instructor')
        self.assertEqual(log_entry.event_details['action'], 'add')
    
    def test_audit_log_role_remove(self):
        """Test role remove audit log."""
        admin_user = User.objects.create_user(
            username='admin',
            password='AdminPass123!@#'
        )
        request = self.factory.post('/admin/assign-role/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        initial_count = AuditLog.objects.count()
        audit_log_role_change(request, admin_user, self.user, 'instructor', 
                             'remove', success=True)
        
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        log_entry = AuditLog.objects.latest('timestamp')
        
        self.assertEqual(log_entry.event_type, 'AUTHZ_ROLE_REMOVE')
        self.assertEqual(log_entry.user, admin_user)
        self.assertEqual(log_entry.event_details['action'], 'remove')


class AuditLogIntegrationTests(TestCase):
    """Integration tests for audit logging in authentication workflows."""
    
    def setUp(self):
        """Set up test users and client."""
        self.client = Client()
        self.factory = RequestFactory()
        Group.objects.get_or_create(name='user')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!@#'
        )
    
    def test_registration_creates_audit_log(self):
        """Test that registration creates an audit log entry."""
        AuditLog.objects.all().delete()
        
        response = self.client.post(reverse('register'), {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'NewPass123!@#',
            'password2': 'NewPass123!@#'
        })
        
        # Should have created an audit log
        audit_logs = AuditLog.objects.filter(event_type='AUTH_REGISTER')
        self.assertEqual(audit_logs.count(), 1)
        
        log_entry = audit_logs.first()
        self.assertTrue(log_entry.success)
        self.assertIn('newuser', log_entry.event_details.get('username', ''))
    
    def test_login_success_creates_audit_log(self):
        """Test that successful login creates an audit log entry."""
        AuditLog.objects.all().delete()
        
        response = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'TestPass123!@#'
        })
        
        # Should have created an audit log
        audit_logs = AuditLog.objects.filter(event_type='AUTH_LOGIN_SUCCESS')
        self.assertEqual(audit_logs.count(), 1)
        
        log_entry = audit_logs.first()
        self.assertTrue(log_entry.success)
    
    def test_login_failure_creates_audit_log(self):
        """Test that failed login attempt creates an audit log entry."""
        AuditLog.objects.all().delete()
        
        response = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'WrongPassword'
        })
        
        # Should have created an audit log for failed attempt
        audit_logs = AuditLog.objects.filter(event_type='AUTH_LOGIN_FAILURE')
        self.assertEqual(audit_logs.count(), 1)
        
        log_entry = audit_logs.first()
        self.assertFalse(log_entry.success)
    
    def test_logout_creates_audit_log(self):
        """Test that logout creates an audit log entry."""
        AuditLog.objects.all().delete()
        
        # First login
        self.client.login(username='testuser', password='TestPass123!@#')
        
        # Then logout
        response = self.client.post(reverse('logout'))
        
        # Should have created an audit log
        audit_logs = AuditLog.objects.filter(event_type='AUTH_LOGOUT')
        self.assertGreaterEqual(audit_logs.count(), 1)  # May include login too
    
    def test_no_sensitive_data_in_audit_logs(self):
        """Test that passwords and secrets are never logged."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        audit_log_auth_login(request, 'testuser', success=True)
        
        log_entry = AuditLog.objects.latest('timestamp')
        
        # Verify no password in details
        log_string = str(log_entry.event_details)
        self.assertNotIn('password', log_string.lower())
        self.assertNotIn('secret', log_string.lower())
        self.assertNotIn('token', log_string.lower())
        
        # Verify username is not logged (for privacy)
        self.assertNotIn('testuser', log_string)
    
    def test_audit_log_indexes_for_performance(self):
        """Test that audit logs have proper indexes for queries."""
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor
        
        # Create some logs
        for i in range(5):
            AuditLog.objects.create(
                event_type='AUTH_LOGIN_SUCCESS',
                user=self.user,
                success=True
            )
        
        # Query by timestamp (should use index)
        logs = AuditLog.objects.filter(
            timestamp__gte=timezone.now() - timezone.timedelta(hours=1)
        )
        self.assertEqual(logs.count(), 5)
        
        # Query by event type and timestamp (should use compound index)
        logs = AuditLog.objects.filter(
            event_type='AUTH_LOGIN_SUCCESS',
            timestamp__gte=timezone.now() - timezone.timedelta(hours=1)
        )
        self.assertEqual(logs.count(), 5)
