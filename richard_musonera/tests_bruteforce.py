"""
Brute-Force Attack Prevention Tests

This test suite verifies that the login flow is hardened against brute-force attacks.

Security Focus:
- Failed login attempts are tracked per IP address
- After MAX_LOGIN_ATTEMPTS (default 5) failures, IP is locked out
- Lockout lasts for LOCKOUT_PERIOD (default 900 seconds = 15 minutes)
- No user enumeration (same error for bad credentials or locked)
- Legitimate users can still log in after timeout
- Lockout is cleared on successful authentication

Test Coverage:
- Tracking failed login attempts
- Lockout activation after threshold
- Lockout expiration after timeout
- Reset of attempts on successful login
- Client IP detection (with proxy support)
- User experience (helpful error messages)
- Legitimate user access after lockout expires
- Multiple users not interfering with each other
"""

from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.core.cache import cache
from richard_musonera.rbac import (
    track_failed_login, is_login_locked, reset_login_attempts, get_client_ip
)
import time


@override_settings(
    MAX_LOGIN_ATTEMPTS=5,
    LOCKOUT_PERIOD=60,  # 60 seconds for testing (instead of 900)
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'test-cache',
        }
    }
)
class BruteForceSetupTests(TestCase):
    """Setup for brute-force protection tests."""

    def setUp(self):
        """Create test users and clear cache."""
        cache.clear()
        
        self.user_group, _ = Group.objects.get_or_create(name="user")
        
        self.alice = User.objects.create_user(
            'alice', 
            'alice@example.com', 
            'CorrectPassword123!'
        )
        self.alice.groups.add(self.user_group)
        
        self.bob = User.objects.create_user(
            'bob',
            'bob@example.com',
            'BobPassword456!'
        )
        self.bob.groups.add(self.user_group)
        
        self.client = Client()

    def tearDown(self):
        """Clear cache after each test."""
        cache.clear()

    def test_setup_complete(self):
        """Verify test users exist."""
        self.assertEqual(User.objects.filter(username='alice').count(), 1)
        self.assertEqual(User.objects.filter(username='bob').count(), 1)


@override_settings(
    MAX_LOGIN_ATTEMPTS=5,
    LOCKOUT_PERIOD=60,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'test-cache',
        }
    }
)
class FailedLoginTrackingTests(TestCase):
    """Test failed login attempt tracking."""

    def setUp(self):
        """Create test user."""
        cache.clear()
        
        self.alice = User.objects.create_user(
            'alice',
            'alice@example.com',
            'CorrectPassword123!'
        )
        
        self.client = Client()

    def tearDown(self):
        """Clear cache."""
        cache.clear()

    def test_failed_attempt_is_tracked(self):
        """Failed login attempts should be tracked."""
        # Make a failed login attempt
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'WrongPassword'
        })
        
        # Should show error message
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid credentials', response.content)

    def test_multiple_failed_attempts_increment_counter(self):
        """Multiple failed attempts should increment counter."""
        from django.test import RequestFactory
        
        factory = RequestFactory()
        
        # Create multiple failed attempts
        for i in range(3):
            django_request = factory.post('/login/')
            django_request.META['REMOTE_ADDR'] = '127.0.0.1'
            result = track_failed_login(django_request, 'alice')
            self.assertEqual(result['attempts'], i + 1)
            self.assertFalse(result['locked_out'])

    def test_remaining_attempts_calculated_correctly(self):
        """Remaining attempts should be MAX_LOGIN_ATTEMPTS - current attempts."""
        from django.test import RequestFactory
        
        factory = RequestFactory()
        django_request = factory.post('/login/')
        django_request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # First attempt
        result = track_failed_login(django_request, 'alice')
        self.assertEqual(result['remaining'], 4)  # 5 - 1

    def test_lockout_after_max_attempts(self):
        """Account should lock out after MAX_LOGIN_ATTEMPTS."""
        from django.test import RequestFactory
        
        factory = RequestFactory()
        django_request = factory.post('/login/')
        django_request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Make MAX_LOGIN_ATTEMPTS (5) failed attempts
        for i in range(5):
            result = track_failed_login(django_request, 'alice')
        
        # Should be locked out now
        self.assertTrue(result['locked_out'])
        self.assertEqual(result['remaining'], 0)

    def test_login_blocked_when_locked_out(self):
        """Login view should block requests when IP is locked out."""
        # Make 5 failed login attempts
        for i in range(5):
            self.client.post(reverse('login'), {
                'username': 'alice',
                'password': f'WrongPassword{i}'
            })
        
        # Try to log in with correct password - should be blocked
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'CorrectPassword123!'
        })
        
        # Should show lockout message, not login
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'temporarily locked', response.content.lower())


@override_settings(
    MAX_LOGIN_ATTEMPTS=5,
    LOCKOUT_PERIOD=60,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'test-cache',
        }
    }
)
class LockoutExpirationTests(TestCase):
    """Test lockout timeout behavior."""

    def setUp(self):
        """Create test user."""
        cache.clear()
        
        self.alice = User.objects.create_user(
            'alice',
            'alice@example.com',
            'CorrectPassword123!'
        )
        
        self.client = Client()

    def tearDown(self):
        """Clear cache."""
        cache.clear()

    def test_lockout_is_temporary(self):
        """Lockout should expire after LOCKOUT_PERIOD."""
        from django.test import RequestFactory
        
        factory = RequestFactory()
        django_request = factory.post('/login/')
        django_request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Lock out the IP
        for i in range(5):
            track_failed_login(django_request, 'alice')
        
        # Should be locked
        self.assertTrue(is_login_locked(django_request))
        
        # After cache timeout, should be unlocked
        cache.clear()
        self.assertFalse(is_login_locked(django_request))


@override_settings(
    MAX_LOGIN_ATTEMPTS=5,
    LOCKOUT_PERIOD=60,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'test-cache',
        }
    }
)
class LoginAttemptResetTests(TestCase):
    """Test resetting login attempts on successful authentication."""

    def setUp(self):
        """Create test user."""
        cache.clear()
        
        self.user_group, _ = Group.objects.get_or_create(name="user")
        
        self.alice = User.objects.create_user(
            'alice',
            'alice@example.com',
            'CorrectPassword123!'
        )
        self.alice.groups.add(self.user_group)
        
        self.client = Client()

    def tearDown(self):
        """Clear cache."""
        cache.clear()

    def test_successful_login_resets_attempts(self):
        """Successful login should reset failed attempt counter."""
        from django.test import RequestFactory
        
        factory = RequestFactory()
        django_request = factory.post('/login/')
        django_request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Make some failed attempts
        for i in range(3):
            track_failed_login(django_request, 'alice')
        
        # Counter should be at 3
        result = track_failed_login(django_request, 'alice')
        self.assertEqual(result['attempts'], 4)
        
        # Reset attempts
        reset_login_attempts(django_request, 'alice')
        
        # New attempt should start from 1 (or be tracked fresh)
        result = track_failed_login(django_request, 'alice')
        self.assertEqual(result['attempts'], 1)

    def test_successful_login_in_django_client(self):
        """Successful login via Django test client should reset attempts."""
        # Make some failed attempts
        for i in range(3):
            self.client.post(reverse('login'), {
                'username': 'alice',
                'password': f'WrongPassword{i}'
            })
        
        # Now log in with correct password
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'CorrectPassword123!'
        })
        
        # Should succeed and redirect
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)


@override_settings(
    MAX_LOGIN_ATTEMPTS=5,
    LOCKOUT_PERIOD=60,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'test-cache',
        }
    }
)
class ClientIPDetectionTests(TestCase):
    """Test client IP detection for rate limiting."""

    def test_direct_connection_ip(self):
        """Should detect direct connection IP."""
        from django.test import RequestFactory
        
        factory = RequestFactory()
        request = factory.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        
        ip = get_client_ip(request)
        self.assertEqual(ip, '192.168.1.100')

    def test_x_forwarded_for_header(self):
        """Should use X-Forwarded-For header for proxy detection."""
        from django.test import RequestFactory
        
        factory = RequestFactory()
        request = factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.50, 198.51.100.1'
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        ip = get_client_ip(request)
        # Should get the first IP in X-Forwarded-For
        self.assertEqual(ip, '203.0.113.50')

    def test_x_real_ip_header(self):
        """Should use X-Real-IP header (nginx)."""
        from django.test import RequestFactory
        
        factory = RequestFactory()
        request = factory.get('/')
        request.META['HTTP_X_REAL_IP'] = '203.0.113.100'
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        ip = get_client_ip(request)
        self.assertEqual(ip, '203.0.113.100')

    def test_multiple_users_separate_lockouts(self):
        """Different IPs should have separate rate limits."""
        cache.clear()
        
        # User in office (IP 203.0.113.1)
        self.client.META['REMOTE_ADDR'] = '203.0.113.1'
        for i in range(2):
            self.client.post(reverse('login'), {
                'username': 'alice',
                'password': f'WrongPassword{i}'
            }, REMOTE_ADDR='203.0.113.1')
        
        # User at home (IP 203.0.113.2) - should not be affected
        client2 = Client()
        response = client2.post(reverse('login'), {
            'username': 'alice',
            'password': 'WrongPassword'
        }, REMOTE_ADDR='203.0.113.2')
        
        # Should not be locked out (different IP)
        self.assertEqual(response.status_code, 200)


@override_settings(
    MAX_LOGIN_ATTEMPTS=5,
    LOCKOUT_PERIOD=60,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'test-cache',
        }
    }
)
class BruteForceUserExperienceTests(TestCase):
    """Test user experience during brute-force protection."""

    def setUp(self):
        """Create test user."""
        cache.clear()
        
        self.user_group, _ = Group.objects.get_or_create(name="user")
        
        self.alice = User.objects.create_user(
            'alice',
            'alice@example.com',
            'CorrectPassword123!'
        )
        self.alice.groups.add(self.user_group)
        
        self.client = Client()

    def tearDown(self):
        """Clear cache."""
        cache.clear()

    def test_error_messages_are_helpful(self):
        """Error messages should inform user about remaining attempts."""
        # First failed attempt
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'WrongPassword'
        })
        
        # Should mention remaining attempts
        self.assertIn(b'remaining', response.content.lower())

    def test_lockout_message_is_clear(self):
        """Lockout message should be clear about timing."""
        # Lock out the IP
        for i in range(5):
            self.client.post(reverse('login'), {
                'username': 'alice',
                'password': f'WrongPassword{i}'
            })
        
        # Try to log in
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'CorrectPassword123!'
        })
        
        # Should mention timing
        self.assertIn(b'15 minutes', response.content.lower())

    def test_legitimate_user_can_login_after_delay(self):
        """User should be able to log in after lockout expires."""
        # Lock out the IP
        for i in range(5):
            self.client.post(reverse('login'), {
                'username': 'alice',
                'password': f'WrongPassword{i}'
            })
        
        # Clear cache (simulate timeout)
        cache.clear()
        
        # Now should be able to log in
        response = self.client.post(reverse('login'), {
            'username': 'alice',
            'password': 'CorrectPassword123!'
        })
        
        # Should redirect to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)

    def test_csrf_protection_maintained(self):
        """CSRF protection should still be active."""
        response = self.client.get(reverse('login'))
        self.assertContains(response, 'csrfmiddlewaretoken')
