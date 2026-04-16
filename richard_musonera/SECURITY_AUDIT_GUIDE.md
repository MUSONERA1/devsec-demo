# RBAC Security Audit Guide

## Overview
This guide provides security professionals and developers with procedures to audit and verify the Role-Based Access Control implementation in the User Authentication Service.

## Quick Audit Checklist

### Infrastructure Audit
- [ ] Django Groups model is properly configured
- [ ] Three roles exist: "user", "instructor", "admin"
- [ ] `role_required` decorator is implemented correctly
- [ ] `@admin_required` decorator provides proper shorthand
- [ ] PermissionDenied exceptions are caught by Django's 403 handler
- [ ] Error responses don't leak sensitive information

### Authorization Audit
- [ ] All protected views use `@role_required()` or `@admin_required`
- [ ] No protected logic exists in templates only (templates can hint, not enforce)
- [ ] URL patterns don't expose authorization logic
- [ ] Views check authentication before checking roles
- [ ] Role assignments use Django Groups, not custom tables

### Access Control Audit
- [ ] Anonymous users cannot access protected pages
- [ ] Users can only access their assigned role areas
- [ ] Role elevation requires explicit admin action (not self-serve)
- [ ] Privilege separation is enforced (user vs admin vs instructor)
- [ ] Multi-role users can access all allowed areas

### Logging and Monitoring
- [ ] Authorization checks are logged
- [ ] Denied access attempts are recorded
- [ ] Logs include username, resource, and reason
- [ ] Log levels are appropriate (WARNING for denial, INFO for approval)

---

## Detailed Audit Procedures

### 1. Infrastructure Verification

#### Django Groups Configuration
```bash
# SSH to server or use Django shell
python manage.py shell
```

```python
from django.contrib.auth.models import Group

# Verify roles exist
roles = ['user', 'instructor', 'admin']
for role in roles:
    group = Group.objects.get(name=role)
    print(f"✓ {role}: {group.id}")

# Check if groups have permissions (optional)
for group in Group.objects.all():
    perms = group.permissions.all().count()
    print(f"{group.name}: {perms} permissions")
```

#### RBAC Module Verification
```python
from richard_musonera.rbac import (
    role_required, admin_required, has_role, has_any_role
)

# Verify decorators exist and are callable
print("✓ role_required:", callable(role_required))
print("✓ admin_required:", callable(admin_required))
print("✓ has_role:", callable(has_role))
print("✓ has_any_role:", callable(has_any_role))
```

### 2. Authorization Coverage Audit

#### Verify All Protected Views
```bash
# Review views.py for @role_required or @admin_required
grep -n "@role_required\|@admin_required" richard_musonera/views.py
```

**Expected Output** (sample):
```
23: @role_required("user")
24: def dashboard_view(request):

51: @login_required(login_url='login')
52: def profile_view(request):

73: @login_required(login_url='login')
74: def password_change_view(request):

89: @role_required("instructor")
90: def instructor_panel(request):

96: @admin_required
97: def admin_dashboard(request):
```

#### Check for Unprotected Sensitive Operations
```bash
# Look for views that might need protection
grep -n "def.*view" richard_musonera/views.py | grep -v "register\|login\|logout"
```

**Security Note**: Registration and login/logout are intentionally unprotected. All other views should have explicit protection.

### 3. Access Control Testing

#### Test Anonymous Access
```bash
curl -i http://localhost:8000/dashboard/
# Expected: 403 Forbidden
```

#### Test User Access
```bash
# Login first
curl -i -c cookies.txt -d "username=testuser&password=pass" \
  http://localhost:8000/login/

# Access user area
curl -i -b cookies.txt http://localhost:8000/dashboard/
# Expected: 200 OK

# Try admin area
curl -i -b cookies.txt http://localhost:8000/admin-panel/
# Expected: 403 Forbidden
```

#### Automated Testing
```bash
python manage.py test richard_musonera.tests_rbac -v 2
```

### 4. Role Assignment Audit

#### Verify Correct Role Assignment
```python
from django.contrib.auth.models import User, Group

# Find all users
for user in User.objects.all():
    roles = list(user.groups.values_list('name', flat=True))
    print(f"{user.username}: {', '.join(roles)}")

# Find all users with admin role
admin_users = User.objects.filter(groups__name='admin')
for user in admin_users:
    print(f"✓ {user.username} is admin")
```

#### Detect Unauthorized Role Assignment
```python
from django.contrib.auth.models import User

# Look for suspicious group assignments
for user in User.objects.all():
    if user.is_superuser and not user.groups.filter(name='admin').exists():
        print(f"⚠️ Superuser {user.username} not in admin group")
    
    if not user.is_active:
        print(f"⚠️ Inactive user {user.username} in groups: " \
              f"{list(user.groups.values_list('name', flat=True))}")
```

### 5. Error Handling Audit

#### Verify Error Pages Don't Leak Info
```bash
# Try to access admin panel as regular user
curl -i http://localhost:8000/admin-panel/

# Check response:
# - Should contain 403 status
# - Should NOT contain SQL queries
# - Should NOT contain file paths
# - Should be user-friendly
```

#### Check Logging
```bash
# Monitor Django logs
tail -f logs/django.log

# Trigger a denied access
# Look for entries like:
# WARNING - User 'testuser' denied access to /admin-panel/
# (has roles: ['user'], requires: ['admin'])
```

### 6. Configuration Audit

#### Verify Settings.py Configuration
```bash
grep -A 20 "INSTALLED_APPS\|MIDDLEWARE" \
  devsec_demo/settings.py
```

**Should include**:
- `'django.contrib.auth'` in INSTALLED_APPS
- `'django.contrib.sessions'` in INSTALLED_APPS
- `'django.middleware.security.SecurityMiddleware'`
- `'django.contrib.sessions.middleware.SessionMiddleware'`
- `'django.contrib.auth.middleware.AuthenticationMiddleware'`

#### Verify URL Configuration
```bash
grep -n "handler403" devsec_demo/urls.py
# Should define custom 403 handler
```

### 7. Security Best Practices Verification

#### Check for Common Vulnerabilities

**IDOR (Insecure Direct Object Reference)**
```python
# Verify users can't access other users' data
# TODO: Implement per-object permission checks if needed
```

**Privilege Escalation**
```python
# Verify users can't modify their own groups
# This should only be possible via admin panel
```

**Broken Access Control**
```bash
# Run security tests
python manage.py test richard_musonera.tests_rbac.AuthenticatedUserAuthorizationTests -v 2
```

**Information Disclosure**
```bash
# Verify errors don't expose system info
curl http://localhost:8000/admin-panel/ 2>&1 | grep -i "traceback\|database\|exception"
# Should return nothing (no sensitiveinfo in response)
```

### 8. Audit Logging

#### Enable Authorization Logging
In Django settings or logging configuration:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': 'logs/authorization.log',
        },
    },
    'loggers': {
        'richard_musonera.rbac': {
            'handlers': ['file'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}
```

#### Review Authorization Logs
```bash
# Find all denied access attempts
grep "denied access" logs/authorization.log

# Find attempts to access specific resources
grep "/admin-panel/" logs/authorization.log

# Count denials per user
grep "denied access" logs/authorization.log | cut -d' ' -f3 | sort | uniq -c | sort -rn
```

### 9. Performance Audit

#### Check Group Lookup Efficiency
```python
from django.db import connection
from django.test.utils import override_settings
from django.contrib.auth.models import User

# Monitor database queries
from django.test import Client

client = Client()
user = User.objects.create_user(username='test', password='pass')

with override_settings(DEBUG=True):
    from django.contrib.auth.models import Group
    g = Group.objects.create(name='test')
    user.groups.add(g)
    
    # Should be minimal queries (likely 1-2)
    print(f"Queries for group check: {len(connection.queries)}")
```

### 10. Audit Report Template

```markdown
## RBAC Security Audit Report
**Date**: [DATE]
**Auditor**: [NAME]
**System**: Django UAS

### Findings Summary
- ✓ All protected views properly decorated
- ✓ Authorization checks logged
- ✓ Error handling is secure
- ⚠️ [Any issues]

### Vulnerabilities
[None found | OR list issues]

### Recommendations
1. [If any]

### Sign-off
- Infrastructure: ✓
- Authorization: ✓
- Access Control: ✓
- Logging: ✓
- Performance: ✓
```

---

## Common Audit Findings and Fixes

### Finding: Unprotected Admin Function
**Issue**: Admin function not using `@admin_required`
```python
# ❌ NOT SECURE
def sensitive_operation(request):
    if request.user.is_staff:
        # Do sensitive thing
```

**Fix**: Use decorator
```python
# ✅ SECURE
@admin_required
def sensitive_operation(request):
    # Do sensitive thing
```

### Finding: Template-Only Access Control
**Issue**: Permission checked only in template
```html
<!-- ❌ NOT SECURE -->
{% if is_admin %}
    {% include "admin_panel.html" %}
{% endif %}
```

**Fix**: Enforce in view
```python
# ✅ SECURE
@admin_required
def admin_panel_view(request):
    return render(request, 'admin_panel.html')
```

### Finding: Information Leakage in Errors
**Issue**: Error page shows system information
```python
# ❌ NOT SECURE (DEBUG=True)
DEBUG = True
```

**Fix**: Disable debug in production
```python
# ✅ SECURE
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'
```

---

## Compliance Checklist

### OWASP Top 10
- [ ] A01: Broken Access Control → RBAC decorators enforce
- [ ] A02: Cryptographic Failures → Django's password hashing
- [ ] A07: Identification and Authentication → Group-based auth

### CWE Top 25
- [ ] CWE-276: Incorrect Default Permissions → Roles explicitly assigned
- [ ] CWE-284: Improper Access Control → RBAC decorators
- [ ] CWE-285: Improper Authorization → Role-required checks

### NIST Guidelines
- [ ] Access Control Policy Defined ✓
- [ ] Least Privilege Enforced ✓
- [ ] Role-Based Access Control ✓
- [ ] Audit Trail Maintained ✓

---

**Last Updated**: April 16, 2026  
**Version**: 1.0
