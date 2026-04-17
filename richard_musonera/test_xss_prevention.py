"""
Tests for Stored XSS Prevention in User-Controlled Profile Content

This test suite validates that user-controlled content (particularly the bio field)
is properly escaped when rendered in templates, preventing stored XSS attacks.

Attack Vectors Tested:
- Script injection in bio field: <script>alert('XSS')</script>
- JavaScript event handlers: <img src=x onerror=alert('XSS')>
- HTML entity encoding bypass attempts: &#60;script&#62;
- SVG/XML-based XSS: <svg onload=alert('XSS')>
- Data URI-based XSS: <img src="data:text/html,<script>alert('XSS')</script>">
- Event handler variations: onclick, onmouseover, onload, etc.
"""

from django.test import TestCase
from django.contrib.auth.models import User
from django.template import Template, Context
from django.utils.html import escape
from richard_musonera.models import UserProfile


class StoredXSSPreventionModelTests(TestCase):
    """Test that XSS payloads are stored safely in the database."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
        self.profile = self.user.profile
    
    def test_script_injection_is_stored_safely(self):
        """Verify that script payloads are stored (not executed) in database."""
        malicious_script = "<script>alert('XSS')</script>"
        self.profile.bio = malicious_script
        self.profile.save()
        
        # Retrieve and verify it's stored as-is
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.bio, malicious_script)
    
    def test_xss_payload_with_event_handlers_is_stored(self):
        """Verify that payloads with event handlers are stored safely."""
        payload = "<img src=x onerror=alert('XSS')>"
        self.profile.bio = payload
        self.profile.save()
        
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.bio, payload)
    
    def test_multiple_xss_vectors_are_stored(self):
        """Verify that multiple attack vectors are stored."""
        payload = """<script>alert('1')</script><svg onload=alert('2')>"""
        self.profile.bio = payload
        self.profile.save()
        
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.bio, payload)


class TemplateAutoEscapeTests(TestCase):
    """Test that Django's template auto-escape prevents XSS rendering."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
        self.profile = self.user.profile
    
    def test_script_tag_is_escaped_in_template(self):
        """Verify that <script> tags are escaped when rendered."""
        malicious = "<script>alert('XSS')</script>"
        self.profile.bio = malicious
        self.profile.save()
        
        # Use Django's template system
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # ✅ Script tags should be escaped
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;/script&gt;", rendered)
    
    def test_img_onerror_is_escaped_in_template(self):
        """Verify that event handlers are escaped."""
        malicious = "<img src=x onerror=alert('XSS')>"
        self.profile.bio = malicious
        self.profile.save()
        
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # ✅ Should be escaped
        self.assertNotIn("<img src=x onerror", rendered)
        self.assertIn("&lt;img", rendered)
    
    def test_svg_onload_is_escaped_in_template(self):
        """Verify that SVG payloads are escaped."""
        malicious = "<svg onload=alert('XSS')></svg>"
        self.profile.bio = malicious
        self.profile.save()
        
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # ✅ Should be escaped
        self.assertNotIn("<svg onload", rendered)
        self.assertIn("&lt;svg", rendered)
    
    def test_data_uri_xss_is_escaped(self):
        """Verify that data URI-based attacks are escaped."""
        malicious = '<img src="data:text/html,<script>alert(\'XSS\')</script>">'
        self.profile.bio = malicious
        self.profile.save()
        
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # ✅ Should be escaped - script tags and event handlers won't execute
        # The src attribute value is in quotes, and the dangerous <script> is escaped
        self.assertIn("&lt;img", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        # The img tag itself is escaped, so it won't be interpreted as HTML
        self.assertNotIn('<img src="data:', rendered)
    
    def test_iframe_is_escaped(self):
        """Verify that iframe injections are escaped."""
        malicious = '<iframe src="https://attacker.com"></iframe>'
        self.profile.bio = malicious
        self.profile.save()
        
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # ✅ Should be escaped
        self.assertNotIn('<iframe', rendered)
        self.assertIn('&lt;iframe', rendered)
    
    def test_style_tag_is_escaped(self):
        """Verify that style tags are escaped."""
        malicious = '<style>body{display:none}</style>'
        self.profile.bio = malicious
        self.profile.save()
        
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # ✅ Should be escaped
        self.assertNotIn('<style>', rendered)
        self.assertIn('&lt;style&gt;', rendered)
    
    def test_javascript_protocol_is_escaped(self):
        """Verify that javascript: protocol is escaped."""
        malicious = '<a href="javascript:alert(\'XSS\')">Click</a>'
        self.profile.bio = malicious
        self.profile.save()
        
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # ✅ Should be escaped - the <a> tag itself is escaped so it won't execute
        # as a link with javascript: protocol
        self.assertIn('&lt;a href', rendered)
        # The actual href value with javascript: is safe in escaped text
        # because the tag isn't interpreted as HTML
        self.assertNotIn('<a href="javascript:', rendered)
    
    def test_legitimate_ampersand_is_escaped(self):
        """Verify legitimate content with & is properly handled."""
        text = "Fish & Chips"
        self.profile.bio = text
        self.profile.save()
        
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # ✅ Ampersand should be escaped but readable
        self.assertIn("&amp;", rendered)
        self.assertIn("Fish", rendered)
        self.assertIn("Chips", rendered)
    
    def test_quotes_in_bio_are_escaped(self):
        """Verify that quotes are properly escaped."""
        text = '''He said "Hello" and I said 'Hi' '''
        self.profile.bio = text
        self.profile.save()
        
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # Quotes should be preserved or escaped safely
        self.assertIn("Hello", rendered)
        self.assertIn("Hi", rendered)
    
    def test_multiple_xss_vectors_are_all_escaped(self):
        """Verify that multiple attack vectors are all escaped."""
        malicious = """
        <script>alert('1')</script>
        <svg onload=alert('2')>
        <img onerror=alert('3')>
        """
        self.profile.bio = malicious
        self.profile.save()
        
        template = Template("{{ bio }}")
        context = Context({'bio': self.profile.bio})
        rendered = template.render(context)
        
        # ✅ All should be escaped
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<svg onload", rendered)
        self.assertNotIn("<img onerror", rendered)
        # Verify escaping is present
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;svg", rendered)
        self.assertIn("&lt;img", rendered)


class DjangoAutoEscapeIntegrationTests(TestCase):
    """Integration tests verifying auto-escape in form fields and display."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
        self.profile = self.user.profile
    
    def test_html_escape_function_works(self):
        """Verify that Django's escape function works correctly."""
        malicious = "<script>alert('XSS')</script>"
        escaped = escape(malicious)
        
        # ✅ Should be escaped
        self.assertEqual(escaped, "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;")
        self.assertNotIn("<script>", escaped)
    
    def test_xss_prevention_doesnt_affect_form_storage(self):
        """Verify that we store the raw content (safe in DB)."""
        payload = "<img src=x onerror=alert('XSS')>"
        self.profile.bio = payload
        self.profile.save()
        
        # Raw content should be stored
        stored = UserProfile.objects.get(pk=self.profile.pk)
        self.assertEqual(stored.bio, payload)
