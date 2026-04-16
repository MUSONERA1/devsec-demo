"""
Simplified Brute-Force Protection Tests (No Django Test Client)

This test suite verifies the brute-force protection logic using RequestFactory
to avoid Python 3.14 compatibility issues with Django's test client context copying.

Focus: Core brute-force utilities
- Tracking failed attempts 
- Lockout detection
- Attempt reset
- IP detection
"""

from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth.models import User, Group
from django.core.cache import cache
from richard_musonera.rbac import (
    track_failed_login, is_login_locked, reset_login_attempts, get_client_ip
)


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

    def setUp(self):
        """Setup request factory."""
        self.factory = RequestFactory()
        cache.clear()

    def tearDown(self):
        """Clear cache."""
        cache.clear()

    def test_direct_connection_ip(self):
        """Should detect direct connection IP from REMOTE_ADDR."""
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        
        ip = get_client_ip(request)
        self.assertEqual(ip, '192.168.1.100')

    def test_x_forwarded_for_header_single(self):
        """Should use single IP in X-Forwarded-For header."""
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.50'
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        ip = get_client_ip(request)
        self.assertEqual(ip, '203.0.113.50')

    def test_x_forwarded_for_header_multiple(self):
        """Should use first IP in X-Forwarded-For list."""
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.50, 198.51.100.1, 192.0.2.1'
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        ip = get_client_ip(request)
        self.assertEqual(ip, '203.0.113.50')

    def test_x_real_ip_header(self):
        """Should use X-Real-IP header (nginx)."""
        request = self.factory.get('/')
        request.META['HTTP_X_REAL_IP'] = '203.0.113.100'
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        ip = get_client_ip(request)
        self.assertEqual(ip, '203.0.113.100')

    def test_x_forwarded_for_precedence_over_remote_addr(self):
        """X-Forwarded-For should take precedence over REMOTE_ADDR."""
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.200'
        request.META['REMOTE_ADDR'] = '192.168.1.50'
        
        ip = get_client_ip(request)
        self.assertEqual(ip, '203.0.113.200')


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
        """Setup for tests."""
        self.factory = RequestFactory()
        cache.clear()

    def tearDown(self):
        """Clear cache."""
        cache.clear()

    def test_single_failed_attempt_tracked(self):
        """Single failed attempt should be tracked."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        result = track_failed_login(request, 'alice')
        
        self.assertEqual(result['attempts'], 1)
        self.assertFalse(result['locked_out'])
        self.assertEqual(result['remaining'], 4)

    def test_multiple_failed_attempts_increment(self):
        """Multiple failed attempts should increment counter."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        for i in range(1, 6):
            result = track_failed_login(request, 'alice')
            self.assertEqual(result['attempts'], i)

    def test_remaining_attempts_calculation(self):
        """Remaining attempts should be correctly calculated."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # 1st attempt
        result = track_failed_login(request, 'alice')
        self.assertEqual(result['remaining'], 4)
        
        # 3rd attempt
        track_failed_login(request, 'alice')
        track_failed_login(request, 'alice')
        result = track_failed_login(request, 'alice')
        self.assertEqual(result['remaining'], 1)

    def test_lockout_after_max_attempts(self):
        """Should lock out after MAX_LOGIN_ATTEMPTS."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Make MAX_LOGIN_ATTEMPTS - 1 attempts
        for i in range(4):
            result = track_failed_login(request, 'alice')
            self.assertFalse(result['locked_out'])
        
        # Final attempt triggers lockout
        result = track_failed_login(request, 'alice')
        self.assertTrue(result['locked_out'])
        self.assertEqual(result['remaining'], 0)

    def test_lockout_check_after_threshold(self):
        """is_login_locked should return True after threshold."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Not locked initially
        self.assertFalse(is_login_locked(request))
        
        # Lock out the IP
        for i in range(5):
            track_failed_login(request, 'alice')
        
        # Should be locked now
        self.assertTrue(is_login_locked(request))


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
        """Setup for tests."""
        self.factory = RequestFactory()
        cache.clear()

    def tearDown(self):
        """Clear cache."""
        cache.clear()

    def test_lockout_is_temporary(self):
        """Lockout should expire when cache expires."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Lock out the IP
        for i in range(5):
            track_failed_login(request, 'alice')
        
        self.assertTrue(is_login_locked(request))
        
        # Clear cache to simulate timeout
        cache.clear()
        
        # Should no longer be locked
        self.assertFalse(is_login_locked(request))

    def test_different_ips_tracked_separately(self):
        """Different IPs should have separate rate limits."""
        request1 = self.factory.post('/login/')
        request1.META['REMOTE_ADDR'] = '203.0.113.1'
        
        request2 = self.factory.post('/login/')
        request2.META['REMOTE_ADDR'] = '203.0.113.2'
        
        # Lock out first IP
        for i in range(5):
            track_failed_login(request1, 'alice')
        
        self.assertTrue(is_login_locked(request1))
        self.assertFalse(is_login_locked(request2))
        
        # Second IP should still be able to attempt
        result = track_failed_login(request2, 'alice')
        self.assertEqual(result['attempts'], 1)


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
        """Setup for tests."""
        self.factory = RequestFactory()
        cache.clear()

    def tearDown(self):
        """Clear cache."""
        cache.clear()

    def test_reset_clears_attempts(self):
        """Successful login should reset attempt counter."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Make 3 failed attempts
        for i in range(3):
            track_failed_login(request, 'alice')
        
        # Verify counter at 3
        result = track_failed_login(request, 'alice')
        self.assertEqual(result['attempts'], 4)
        
        # Reset attempts
        reset_login_attempts(request, 'alice')
        
        # Next attempt should start fresh
        result = track_failed_login(request, 'alice')
        self.assertEqual(result['attempts'], 1)

    def test_reset_allows_login_after_lockout(self):
        """Resetting should allow login even if previously locked."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Lock out the IP
        for i in range(5):
            track_failed_login(request, 'alice')
        
        self.assertTrue(is_login_locked(request))
        
        # Reset
        reset_login_attempts(request, 'alice')
        
        # Should no longer be locked
        self.assertFalse(is_login_locked(request))


@override_settings(
    MAX_LOGIN_ATTEMPTS=3,  # Lower for easy testing
    LOCKOUT_PERIOD=60,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'test-cache',
        }
    }
)
class BruteForceIntegrationTests(TestCase):
    """Integration tests for brute-force protection flow."""

    def setUp(self):
        """Setup for tests."""
        self.factory = RequestFactory()
        cache.clear()

    def tearDown(self):
        """Clear cache."""
        cache.clear()

    def test_complete_brute_force_scenario(self):
        """Test complete attack-then-recovery scenario."""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.0.2.100'
        
        # Attacker makes 3 failed attempts
        for i in range(3):
            result = track_failed_login(request, 'bob')
            if i < 2:
                self.assertFalse(result['locked_out'])
        
        # Now should be locked
        self.assertTrue(is_login_locked(request))
        
        # Cache clear (timeout passes)
        cache.clear()
        
        # Can try again
        self.assertFalse(is_login_locked(request))
        
        # Successful login resets counter
        reset_login_attempts(request, 'bob')
        
        # Can attempt again without lockout
        result = track_failed_login(request, 'bob')
        self.assertEqual(result['attempts'], 1)

    def test_legitimate_user_recovery(self):
        """Legitimate user should recover when lockout expires."""
        request_alice = self.factory.post('/login/')
        request_alice.META['REMOTE_ADDR'] = '192.0.2.50'
        
        # 2 failed attempts (forgot password, typo)
        for i in range(2):
            track_failed_login(request_alice, 'alice')
        
        # Still able to login
        self.assertFalse(is_login_locked(request_alice))
        
        # One more failed attempt locks out
        track_failed_login(request_alice, 'alice')
        self.assertTrue(is_login_locked(request_alice))
        
        # After remembering password and cache timeout
        cache.clear()
        
        # Can login again
        self.assertFalse(is_login_locked(request_alice))
