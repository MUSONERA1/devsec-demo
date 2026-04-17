"""
Tests for Safe Redirect Handling (Task #38)

Ensures that:
- Redirect targets are validated before use
- Untrusted external redirect destinations are rejected safely
- Legitimate internal navigation still works correctly
- Tests cover safe and unsafe redirect cases
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from .rbac import is_safe_redirect_url, get_safe_redirect


class SafeRedirectValidationTests(TestCase):
    """
    Tests for is_safe_redirect_url function.
    
    Ensures that:
    - Relative URLs (starting with /) are allowed
    - External URLs are rejected
    - Protocol-relative URLs are rejected
    - Dangerous protocols (javascript:, data:) are rejected
    """
    
    def test_safe_relative_urls_are_allowed(self):
        """Relative URLs starting with / should be allowed."""
        safe_urls = [
            '/dashboard/',
            '/profile/',
            '/admin/users/',
            '/profile/',
            '/',
        ]
        for url in safe_urls:
            with self.subTest(url=url):
                self.assertTrue(
                    is_safe_redirect_url(url),
                    f"Relative URL '{url}' should be safe"
                )
    
    def test_external_urls_are_rejected(self):
        """External URLs should be rejected."""
        unsafe_urls = [
            'https://example.com/',
            'http://evil.com/phishing',
            'https://google.com',
            'http://localhost:8000/dashboard',
        ]
        for url in unsafe_urls:
            with self.subTest(url=url):
                self.assertFalse(
                    is_safe_redirect_url(url),
                    f"External URL '{url}' should not be safe"
                )
    
    def test_protocol_relative_urls_are_rejected(self):
        """Protocol-relative URLs (//) should be rejected (XSS/redirect risk)."""
        unsafe_urls = [
            '//example.com/',
            '//evil.com/phishing',
            '//localhost:8000/',
        ]
        for url in unsafe_urls:
            with self.subTest(url=url):
                self.assertFalse(
                    is_safe_redirect_url(url),
                    f"Protocol-relative URL '{url}' should not be safe"
                )
    
    def test_javascript_urls_are_rejected(self):
        """JavaScript URLs should be rejected (XSS prevention)."""
        unsafe_urls = [
            'javascript:alert("xss")',
            'JavaScript:alert("xss")',
            'JAVASCRIPT:alert("xss")',
            'javascript:window.location="http://evil.com"',
        ]
        for url in unsafe_urls:
            with self.subTest(url=url):
                self.assertFalse(
                    is_safe_redirect_url(url),
                    f"JavaScript URL '{url}' should not be safe"
                )
    
    def test_data_urls_are_rejected(self):
        """Data URLs should be rejected (XSS prevention)."""
        unsafe_urls = [
            'data:text/html,<script>alert("xss")</script>',
            'data:text/html,<img src=x onerror=alert("xss")>',
            'DATA:text/html,<script>alert("xss")</script>',
        ]
        for url in unsafe_urls:
            with self.subTest(url=url):
                self.assertFalse(
                    is_safe_redirect_url(url),
                    f"Data URL '{url}' should not be safe"
                )
    
    def test_vbscript_urls_are_rejected(self):
        """VBScript URLs should be rejected (historical XSS)."""
        unsafe_urls = [
            'vbscript:msgbox("xss")',
            'VBScript:msgbox("xss")',
        ]
        for url in unsafe_urls:
            with self.subTest(url=url):
                self.assertFalse(
                    is_safe_redirect_url(url),
                    f"VBScript URL '{url}' should not be safe"
                )
    
    def test_empty_url_is_rejected(self):
        """Empty or None URLs should be rejected."""
        unsafe_urls = [
            '',
            None,
            '   ',  # Whitespace only
        ]
        for url in unsafe_urls:
            with self.subTest(url=url):
                self.assertFalse(
                    is_safe_redirect_url(url),
                    f"Empty URL '{url}' should not be safe"
                )
    
    def test_whitespace_is_stripped(self):
        """Whitespace should be stripped before validation."""
        # Valid URL with whitespace should be detected as valid
        self.assertTrue(is_safe_redirect_url('  /dashboard/  '))
        # Invalid URL with whitespace should still be invalid
        self.assertFalse(is_safe_redirect_url('  //evil.com/  '))


class GetSafeRedirectTests(TestCase):
    """Tests for get_safe_redirect convenience function."""
    
    def test_valid_url_is_returned(self):
        """Valid URLs should be returned as-is."""
        url = '/dashboard/'
        result = get_safe_redirect(url)
        self.assertEqual(result, url)
    
    def test_invalid_url_uses_fallback(self):
        """Invalid URLs should use the fallback."""
        url = 'https://evil.com/'
        result = get_safe_redirect(url, fallback_url='dashboard')
        self.assertEqual(result, 'dashboard')
    
    def test_empty_url_uses_fallback(self):
        """Empty URLs should use the fallback."""
        result = get_safe_redirect('', fallback_url='profile')
        self.assertEqual(result, 'profile')
    
    def test_custom_fallback_is_used(self):
        """Custom fallback URLs should be used when provided."""
        result = get_safe_redirect('//evil.com', fallback_url='/my-custom-page/')
        self.assertEqual(result, '/my-custom-page/')


class LoginRedirectTests(TestCase):
    """Integration tests for login with safe redirects."""
    
    def setUp(self):
        """Set up test user and client."""
        self.client = Client()
        self.user_group, _ = Group.objects.get_or_create(name='user')
        self.user = User.objects.create_user(
            username='testuser',
            password='TestPass123!@#',
            email='test@example.com'
        )
        self.user.groups.add(self.user_group)
    
    def test_login_without_next_redirects_to_dashboard(self):
        """Login without 'next' parameter should redirect to dashboard."""
        response = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'TestPass123!@#'
        }, follow=False)
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)
    
    def test_login_with_safe_next_redirects_to_next(self):
        """Login with valid 'next' parameter should redirect to it."""
        response = self.client.post(
            reverse('login'),
            {
                'username': 'testuser',
                'password': 'TestPass123!@#',
                'next': '/profile/'
            },
            follow=False
        )
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('/profile/', response.url)
    
    def test_login_with_unsafe_next_redirects_to_dashboard(self):
        """Login with unsafe 'next' parameter should redirect to dashboard."""
        response = self.client.post(
            reverse('login'),
            {
                'username': 'testuser',
                'password': 'TestPass123!@#',
                'next': 'https://evil.com/'
            },
            follow=False
        )
        
        self.assertEqual(response.status_code, 302)
        # Should redirect to dashboard, not evil.com
        self.assertIn('/dashboard/', response.url)
        self.assertNotIn('evil.com', response.url)
    
    def test_login_with_external_url_next_rejected(self):
        """Login with external URL 'next' should be rejected safely."""
        response = self.client.post(
            reverse('login'),
            {
                'username': 'testuser',
                'password': 'TestPass123!@#',
                'next': 'http://attacker.com/phishing'
            },
            follow=False
        )
        
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('attacker.com', response.url)
    
    def test_login_with_javascript_url_next_rejected(self):
        """Login with javascript: URL 'next' should be rejected."""
        response = self.client.post(
            reverse('login'),
            {
                'username': 'testuser',
                'password': 'TestPass123!@#',
                'next': 'javascript:alert("xss")'
            },
            follow=False
        )
        
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('javascript', response.url)
        self.assertIn('/dashboard/', response.url)
    
    def test_login_with_protocol_relative_url_next_rejected(self):
        """Login with protocol-relative URL 'next' should be rejected."""
        response = self.client.post(
            reverse('login'),
            {
                'username': 'testuser',
                'password': 'TestPass123!@#',
                'next': '//evil.com/'
            },
            follow=False
        )
        
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('evil.com', response.url)
        self.assertIn('/dashboard/', response.url)


class RegisterRedirectTests(TestCase):
    """Integration tests for registration with safe redirects."""
    
    def setUp(self):
        """Set up test client."""
        self.client = Client()
        # Create the 'user' group
        Group.objects.get_or_create(name='user')
    
    def test_register_without_next_redirects_to_dashboard(self):
        """Registration without 'next' parameter should redirect to dashboard."""
        response = self.client.post(
            reverse('register'),
            {
                'username': 'newuser',
                'email': 'newuser@example.com',
                'password1': 'TestPass123!@#',
                'password2': 'TestPass123!@#'
            },
            follow=False
        )
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)
    
    def test_register_with_safe_next_redirects_to_next(self):
        """Registration with valid 'next' parameter should redirect to it."""
        response = self.client.post(
            reverse('register'),
            {
                'username': 'newuser2',
                'email': 'newuser2@example.com',
                'password1': 'TestPass123!@#',
                'password2': 'TestPass123!@#',
                'next': '/profile/'
            },
            follow=False
        )
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('/profile/', response.url)
    
    def test_register_with_unsafe_redirect_ignored(self):
        """Registration with unsafe 'next' should ignore it safely."""
        response = self.client.post(
            reverse('register'),
            {
                'username': 'newuser3',
                'email': 'newuser3@example.com',
                'password1': 'TestPass123!@#',
                'password2': 'TestPass123!@#',
                'next': 'https://evil.com/steal-data'
            },
            follow=False
        )
        
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('evil.com', response.url)
        self.assertIn('/dashboard/', response.url)


class LoginNextParameterInGetTests(TestCase):
    """
    Tests that 'next' parameter can be passed via GET and appears in login form.
    """
    
    def setUp(self):
        """Set up test client."""
        self.client = Client()
    
    def test_safe_next_parameter_in_get_appears_in_form(self):
        """Safe 'next' parameter in GET should appear in login form."""
        response = self.client.get(reverse('login') + '?next=/profile/')
        self.assertEqual(response.status_code, 200)
        # Check that the 'next' value is in the response
        self.assertIn('/profile/', response.content.decode())
    
    def test_unsafe_next_parameter_in_get_not_in_form(self):
        """Unsafe 'next' parameter in GET should not appear in login form."""
        response = self.client.get(reverse('login') + '?next=https://evil.com/')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        # The unsafe URL should not be in the form
        self.assertNotIn('evil.com', content)
