# Django Security Hardening Configuration

## Overview

This document details the security hardening applied to the Django deployment configuration for DevSecDemo. The configuration addresses common security misconfigurations and implements production-grade security best practices.

**Learning Objective**: Students understand how Django framework settings directly impact security posture and how to properly configure a production deployment.

---

## Security Improvements Summary

### 1. Secret Key Management

**Vulnerability**: Insecure default secret keys compromise session security and CSRF tokens.

**Implementation**:
```python
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    if os.environ.get('DJANGO_ENV') == 'production':
        raise ValueError("DJANGO_SECRET_KEY required in production")
    warnings.warn("Using development default for SECRET_KEY")
    SECRET_KEY = 'django-insecure-dev-key-only-for-development'
```

**Why This Matters**:
- 🔐 Fails loudly if production deployment lacks a secret key
- 🚫 Prevents accidental deployment with development defaults
- ⚙️ Environment-driven configuration enables secure secret rotation

**Production Deployment**:
```bash
# Generate a strong secret key
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

# Set in production
export DJANGO_SECRET_KEY="your-generated-key-here"
```

---

### 2. Debug Mode Control

**Vulnerability**: `DEBUG=True` in production exposes:
- Stack traces with sensitive code paths
- Database queries and credentials
- Environment variables
- Source code snippets

**Implementation**:
```python
IS_PRODUCTION = DJANGO_ENV == 'production'
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'
if DEBUG and IS_PRODUCTION:
    raise ValueError("DEBUG cannot be True in production")
```

**Why This Matters**:
- ❌ Prevents information disclosure to attackers
- 🛡️ Fails loudly on misconfiguration rather than silently running
- 📋 Explicit environment awareness prevents configuration drift

**Production Deployment**:
```bash
# Ensure DEBUG is False
export DJANGO_ENV=production
export DJANGO_DEBUG=False
```

---

### 3. Allowed Hosts Validation

**Vulnerability**: Host Header Injection attacks can:
- Cache poisoning
- Password reset poisoning
- SSRF attacks via Host header

**Implementation**:
```python
if IS_PRODUCTION:
    allowed_hosts_env = os.environ.get('ALLOWED_HOSTS', '')
    if not allowed_hosts_env:
        raise ValueError("ALLOWED_HOSTS required in production")
    ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_env.split(',')]
else:
    ALLOWED_HOSTS = os.environ.get(
        'ALLOWED_HOSTS',
        '127.0.0.1,localhost,[::1]'
    ).split(',')
```

**Why This Matters**:
- 🚫 Prevents Host Header Injection attacks
- 🏠 Production requires explicit host configuration
- 🔍 Development allows localhost testing

**Production Deployment**:
```bash
export ALLOWED_HOSTS="example.com,www.example.com,api.example.com"
```

---

### 4. Session Cookie Security

**Vulnerability**: Insecure session cookies can be:
- Transmitted over HTTP (man-in-the-middle attacks)
- Accessed by JavaScript (XSS attacks)
- Sent cross-site (CSRF attacks)

**Implementation**:
```python
SESSION_COOKIE_SECURE = IS_PRODUCTION      # HTTPS only
SESSION_COOKIE_HTTPONLY = True             # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Strict'         # Same-site requests only
SESSION_COOKIE_AGE = 3600                  # 1 hour expiry
```

**Why This Matters**:
- 🔒 `SECURE`: Only transmitted over HTTPS (protects from network sniffing)
- 🚫 `HTTPONLY`: Prevents JavaScript from stealing cookies (XSS mitigation)
- 🔐 `SAMESITE=Strict`: Only sends cookie to same site (CSRF mitigation)
- ⏱️ `AGE`: Limits session validity window (reduces compromise window)

**Security Impact**:
- Protects against man-in-the-middle attacks
- Mitigates XSS attacks
- Provides defense-in-depth against CSRF

---

### 5. CSRF Cookie Security

**Vulnerability**: Vulnerable CSRF tokens can be:
- Stolen via XSS
- Used in cross-site requests
- Transmitted insecurely

**Implementation**:
```python
CSRF_COOKIE_SECURE = IS_PRODUCTION  # HTTPS only
CSRF_COOKIE_HTTPONLY = True         # No JavaScript access
CSRF_COOKIE_SAMESITE = 'Strict'     # Same-site requests only
```

**Why This Matters**:
- 🛡️ Same protection as session cookies but for CSRF tokens
- 🔐 Creates layered defense against CSRF attacks

---

### 6. Security Headers

#### X-Frame-Options (Clickjacking Protection)
```python
X_FRAME_OPTIONS = 'DENY'  # Prevent framing
```

**Prevents**:
- Clickjacking attacks (transparent iframe overlays)
- UI Redressing attacks
- Malicious frame embedding

#### Content-Security-Policy (XSS Prevention)
```python
SECURE_CONTENT_SECURITY_POLICY = {
    'default-src': ("'self'",),          # Default: same-origin only
    'script-src': ("'self'",),           # No inline scripts
    'style-src': ("'self'", "'unsafe-inline'"),  # Some inline styles for Bootstrap
    'img-src': ("'self'", 'data:', 'https:'),
    'font-src': ("'self'", 'https://cdnjs.cloudflare.com'),
    'frame-ancestors': ("'none'",),      # Never frame this site
}
```

**Prevents**:
- Cross-site scripting (XSS) attacks
- Injection of malicious scripts
- Data exfiltration via images/forms

#### X-Content-Type-Options (MIME-Type Sniffing)
```python
SECURE_CONTENT_TYPE_NOSNIFF = True
```

**Prevents**:
- Browsers misinterpreting file types
- Executing CSS/JavaScript as content types

#### X-XSS-Protection (Legacy XSS Protection)
```python
SECURE_BROWSER_XSS_FILTER = True
```

**Prevents**:
- Legacy XSS attacks in older browsers

---

### 7. HSTS (HTTP Strict Transport Security)

**Vulnerability**: Man-in-the-middle attacks downgrading HTTPS to HTTP.

**Implementation**:
```python
SECURE_HSTS_SECONDS = 31536000 if IS_PRODUCTION else 0  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = IS_PRODUCTION
SECURE_HSTS_PRELOAD = IS_PRODUCTION
SECURE_SSL_REDIRECT = IS_PRODUCTION
```

**Why This Matters**:
- 🔒 Browser enforces HTTPS-only for 1 year
- 🔏 Prevents protocol downgrade attacks
- 🌐 Included in browser HSTS preload list
- 🔀 Automatic redirect from HTTP to HTTPS

**Security Impact**:
```
User visits http://example.com
  ↓ (Browser redirects based on HSTS)
  → https://example.com (encrypted connection)
```

---

### 8. Password Validation Hardening

**Vulnerability**: Weak password acceptance compromises user accounts.

**Implementation**:
```python
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,  # Increased from 8 to 12
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]
```

**Why This Matters**:
- 📏 12-character minimum (strong against brute-force)
- 📋 Rejects common passwords (leaked password databases)
- 🚫 Rejects passwords similar to username/email
- 0️⃣ Rejects all-numeric passwords

---

### 9. Email Backend Validation

**Vulnerability**: Development email backends (console, file) expose emails in production logs.

**Implementation**:
```python
if IS_PRODUCTION:
    EMAIL_BACKEND = os.environ.get(
        'EMAIL_BACKEND',
        'django.core.mail.backends.smtp.EmailBackend'
    )
    # Validate SMTP configuration exists
    required_vars = ['EMAIL_HOST', 'EMAIL_PORT']
    missing_vars = [v for v in required_vars if not os.environ.get(v)]
    if missing_vars:
        raise ValueError(f"Missing email configuration: {missing_vars}")
else:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```

**Why This Matters**:
- 📧 Production MUST use proper email service
- 🔐 Prevents password reset tokens from being exposed in logs
- ⚠️ Fails loudly if email configuration is incomplete

---

### 10. Production Logging

**Vulnerability**: Inadequate logging prevents security incident investigation.

**Implementation**:
```python
LOGGING = {
    'handlers': {
        'console': { ... },
        'file': {  # Only in production
            'filename': '/var/log/django/django.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
        },
        'security': {  # Security-specific logging
            'filename': '/var/log/django/security.log',
            'level': 'WARNING',
        }
    }
}
```

**Why This Matters**:
- 📝 Comprehensive audit trail for security investigation
- 🔍 Security events separated from application logs
- 📏 Log rotation prevents disk space exhaustion

**Logs Capture**:
- Authentication events
- Permission errors
- Security warnings
- Suspicious activity patterns

---

### 11. Static Files Production Setup

**Implementation**:
```python
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles' if IS_PRODUCTION else None
```

**Process**:
```bash
# Before deployment, collect all static files
python manage.py collectstatic --noinput
```

**Why This Matters**:
- 📦 Bundles all static assets for efficient serving
- ⚡ Can be served by CDN or separate web server
- 🔒 Production-ready static file handling

---

### 12. Environment Handling

**Vulnerability**: Hardcoded configuration or implicit assumptions lead to misconfiguration.

**Implementation**:
```python
# Explicit environment variable handling
DJANGO_ENV = os.environ.get('DJANGO_ENV', 'development')
IS_PRODUCTION = DJANGO_ENV == 'production'
IS_DEVELOPMENT = DJANGO_ENV == 'development'

# Fail loudly on misconfiguration
if IS_PRODUCTION and not os.environ.get('DJANGO_SECRET_KEY'):
    raise ValueError("DJANGO_SECRET_KEY required in production")
```

**Why This Matters**:
- ✅ Explicit configuration prevents implicit assumptions
- 🚨 Fails loudly rather than silently using insecure defaults
- 🔄 Environment-driven configuration enables reproducible deployments

---

## Deployment Checklist

### Pre-Deployment
- [ ] Generate and securely store `DJANGO_SECRET_KEY`
- [ ] Set `DJANGO_ENV=production`
- [ ] Set `DJANGO_DEBUG=False`
- [ ] Configure `ALLOWED_HOSTS` for your domain
- [ ] Configure email SMTP backend (SendGrid, AWS SES, etc.)
- [ ] Set up Redis/Memcached for caching
- [ ] Configure database (PostgreSQL recommended over SQLite)
- [ ] Create logs directory with appropriate permissions
- [ ] Generate SSL/TLS certificate (Let's Encrypt recommended)

### Deployment
```bash
# 1. Collect static files
python manage.py collectstatic --noinput

# 2. Run database migrations
python manage.py migrate

# 3. Enable HSTS in settings
SECURE_HSTS_SECONDS=31536000

# 4. Configure web server (Nginx/Apache)
# - Serve static files
# - Proxy requests to Django via Gunicorn/uWSGI
# - Enable HTTPS with strong cipher suites

# 5. Set environment variables
export DJANGO_ENV=production
export DJANGO_SECRET_KEY=your-key
export ALLOWED_HOSTS=example.com,www.example.com
export EMAIL_HOST=smtp.gmail.com
export EMAIL_HOST_USER=your-email
export EMAIL_HOST_PASSWORD=your-password
export REDIS_URL=redis://cache:6379/0

# 6. Start Django application
gunicorn devsec_demo.wsgi:application
```

### Verification
```bash
# Check configuration
python manage.py check --deploy

# Review Django security warnings
python manage.py check --deploy 2>&1 | grep -i "warning\|error"

# Test HTTPS redirect
curl -I http://example.com  # Should redirect to HTTPS

# Verify security headers
curl -I https://example.com | grep -i "strict-transport\|x-frame\|x-content"
```

---

## Security Headers Explained

### What Each Header Prevents

| Header | Protection | Example Attack |
|--------|-----------|----------|
| `X-Frame-Options: DENY` | Clickjacking | Malicious site embeds yours in iframe |
| `X-Content-Type-Options: nosniff` | MIME sniffing | CSS file served as JavaScript |
| `X-XSS-Protection` | Legacy XSS | Inline script injection (old browsers) |
| `Content-Security-Policy` | XSS/Injection | Malicious script execution |
| `Strict-Transport-Security` | Protocol downgrade | MITM on HTTP downgrade |
| `CSRF tokens` | Form hijacking | Cross-site form submission |

---

## Configuration Validation

### Django Check Command
```bash
# Standard development check
python manage.py check

# Production-specific checks
python manage.py check --deploy

# Expected output (development)
System check identified no issues (0 silenced)

# Check with warnings
python manage.py check --deploy 2>&1 | less
```

### Manual Verification

**Check SECRET_KEY is not default**:
```bash
python manage.py shell -c "from django.conf import settings; print('OK' if 'insecure' not in settings.SECRET_KEY else 'FAIL')"
```

**Check DEBUG mode**:
```bash
python manage.py shell -c "from django.conf import settings; print(f'DEBUG={settings.DEBUG}')"
```

**Check ALLOWED_HOSTS**:
```bash
python manage.py shell -c "from django.conf import settings; print(settings.ALLOWED_HOSTS)"
```

**Check Security Headers**:
```bash
curl -I https://example.com
# Look for:
# Strict-Transport-Security
# X-Frame-Options
# X-Content-Type-Options
```

---

## Production Troubleshooting

### Issue: "ALLOWED_HOSTS doesn't match any of these"
**Solution**: Update `ALLOWED_HOSTS` environment variable
```bash
export ALLOWED_HOSTS="example.com,www.example.com,*.example.com"
```

### Issue: "CSRF token missing or incorrect"
**Possible causes**:
- Session cookies not secure
- CSRF cookie not secure
- Missing `{% csrf_token %}` in form
- Browser not sending cookies

**Solution**: Verify CSRF settings and HTTPS configuration

### Issue: "Email not sending in production"
**Possible causes**:
- EMAIL_BACKEND set to 'console' backend
- SMTP credentials incorrect
- Firewall blocking SMTP port

**Solution**: 
```bash
# Test SMTP connection
python manage.py shell
>>> from django.core.mail import send_mail
>>> send_mail('Test', 'Body', 'from@example.com', ['to@example.com'])
```

### Issue: "Static files not loading (404)"
**Solution**: 
```bash
# Collect static files
python manage.py collectstatic --noinput

# Configure web server to serve from STATIC_ROOT
```

---

## Existing Behavior Verification

### Tests Still Pass
```bash
python manage.py test
# All existing tests should pass with hardened configuration
```

### Functional Verification
- [x] User registration works
- [x] User login works
- [x] Profile upload works
- [x] Password reset works
- [x] Dashboard displays correctly
- [x] All URLs are accessible with proper authentication

## Summary of Changes

### Configuration Improvements
1. ✅ Secret key management - Fails loudly in production if not set
2. ✅ Debug mode - Cannot be True in production
3. ✅ Allowed hosts - Must be explicitly configured in production
4. ✅ Session cookies - Secure, HTTPOnly, SameSite=Strict
5. ✅ CSRF cookies - Secure, HTTPOnly, SameSite=Strict
6. ✅ Security headers - Comprehensive XSS, clickjacking, MIME sniffing protection
7. ✅ HSTS - Forces HTTPS for 1 year, prevents downgrade attacks
8. ✅ Password validation - 12-character minimum + common password check
9. ✅ Email backend - Validates SMTP configuration in production
10. ✅ Logging - Production-grade audit logging with rotation
11. ✅ Static files - Production-ready collection setup
12. ✅ Environment handling - Explicit, fail-fast design

### Design Principles Applied
- **Fail-Secure**: Fails loudly on misconfiguration rather than silently using insecure defaults
- **Explicit**: All configuration is explicit, requiring active decision-making
- **Environment-Driven**: Configuration adapts to deployment environment
- **Defense-in-Depth**: Multiple layers of security (headers, cookies, validation)
- **Audit Trail**: Production logging enables security investigation

---

## References

- [Django Security Documentation](https://docs.djangoproject.com/en/stable/topics/security/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Security Headers](https://securityheaders.com/)
- [HSTS Preload](https://hstspreload.org/)
