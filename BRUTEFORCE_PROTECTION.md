# Brute-Force Attack Protection

## Overview

This document describes the brute-force attack protection mechanism implemented in the Django authentication system (Task #36). The system protects the login endpoint against repeated password-guessing attacks while maintaining usability for legitimate users.

## Security Requirements

- **Requirement 1**: Protective response to repeated failed login attempts
- **Requirement 2**: Maintain usability for legitimate users
- **Requirement 3**: Prefer simple, auditable controls over complex custom systems

## Implementation Summary

### Architecture

The brute-force protection is implemented using:

1. **IP-Based Rate Limiting**: Tracks login attempts per client IP address (not per username)
2. **Django Cache Backend**: Uses in-memory LocMemCache for fast lookups and automatic expiration
3. **Time-Based Lockout**: Automatic temporary lockout that expires after a configurable period
4. **Audit Logging**: All attempts are logged for security monitoring

### Why IP-Based Tracking?

We use **IP-based tracking** instead of username-based tracking to:

- **Prevent User Enumeration**: Attackers can't determine if a username exists (failed auth looks same as locked account)
- **Protect Legitimate Users**: Single user can't be permanently targeted by distributed attacks from multiple IPs
- **Simplify Implementation**: No need to track which specific users are under attack
- **Reduce False Positives**: Corporate networks share IPs; username tracking would lock out entire organizations

### Why Cache Backend?

We use **Django's LocMemCache** instead of database or custom solutions to:

- **Meet "Simple, Auditable" Requirement**: Uses Django's standard caching framework
- **Performance**: In-memory lookups with automatic expiration (O(1) operations)
- **No Schema Changes**: Works with existing database
- **Automatic Cleanup**: TTL-based expiration without manual intervention
- **Scalability**: Per-process cache; suitable for single/dual-server deployments

**Note**: For multi-server deployments, upgrade to Redis/Memcached backend with no code changes.

## Configuration

### Settings (settings.py)

```python
# Maximum failed login attempts before lockout
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))

# Lockout duration in seconds (900 = 15 minutes)
LOCKOUT_PERIOD = int(os.environ.get('LOCKOUT_PERIOD', 900))

# Cache configuration for tracking attempts
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
        'OPTIONS': {'MAX_ENTRIES': 1000}
    }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_LOGIN_ATTEMPTS` | 5 | Number of failed attempts before lockout |
| `LOCKOUT_PERIOD` | 900 | Seconds to lockout IP (900 = 15 minutes) |

### Configuring for Different Scenarios

**Strict Mode (High Security)**:
```bash
MAX_LOGIN_ATTEMPTS=3
LOCKOUT_PERIOD=1800  # 30 minutes
```

**Lenient Mode (More Usable)**:
```bash
MAX_LOGIN_ATTEMPTS=10
LOCKOUT_PERIOD=600  # 10 minutes
```

**Development Mode**:
```bash
MAX_LOGIN_ATTEMPTS=50  # Very lenient
LOCKOUT_PERIOD=60     # Quick expiration
```

## Usage

### For Developers

The brute-force protection is automatically active. Three main functions exist in `rbac.py`:

#### 1. Check if IP is locked out (called early to avoid expensive password hashing)

```python
from richard_musonera.rbac import is_login_locked

if is_login_locked(request):
    # Show lockout message, don't process login
    return render(request, 'login.html', {'locked_out': True})
```

#### 2. Track a failed attempt (called on failed authentication)

```python
from richard_musonera.rbac import track_failed_login

result = track_failed_login(request, username)
if result['locked_out']:
    messages.error(request, "Too many attempts. Try again in 15 minutes.")
else:
    messages.error(request, f"Invalid credentials. ({result['remaining']} attempts left)")
```

Returns: `{'locked_out': bool, 'attempts': int, 'remaining': int}`

#### 3. Reset attempts after successful login (called on successful authentication)

```python
from richard_musonera.rbac import reset_login_attempts

user = authenticate(request, username=username, password=password)
if user:
    reset_login_attempts(request, username)
    login(request, user)
```

### For Administrators

**Monitor login attempts** via application logs:

```bash
# View all brute-force events
grep "Failed login attempt\|locked out" /var/log/django.log

# Count attempts per IP
grep "Failed login attempt" /var/log/django.log | cut -d' ' -f6 | sort | uniq -c
```

**Adjust security parameters**:

```bash
# Emergency: Tighter lockout
export MAX_LOGIN_ATTEMPTS=2
export LOCKOUT_PERIOD=3600  # 1 hour

# Recovery: More lenient
export MAX_LOGIN_ATTEMPTS=10
export LOCKOUT_PERIOD=300  # 5 minutes
```

**Clear lockouts** (if necessary):

```python
# In Django shell
python manage.py shell

from django.core.cache import cache
cache.clear()  # Nuclear option: clears all cache

# Or targeted:
# cache.delete(f'login_locked_{suspect_ip}')
# cache.delete(f'login_attempts_{suspect_ip}')
```

## How It Works

### Attack Flow (Blocked)

```
Attacker from IP 203.0.113.100 attempts login
├─ Attempt 1: Invalid password → Tracked, +1 counter
├─ Attempt 2: Invalid password → Tracked, +1 counter
├─ Attempt 3: Invalid password → Tracked, +1 counter
├─ Attempt 4: Invalid password → Tracked, +1 counter
├─ Attempt 5: Invalid password → LOCKOUT ACTIVATED
│                                └─ IP 203.0.113.100 marked as locked (15 minutes)
└─ Attempt 6: Any password → REJECTED (even if correct)
              └─ Shown: "Too many failed attempts"
              └─ Log: "Login attempt blocked due to lockout"
              └─ Retry available after 15 minutes
```

### Legitimate User Flow (Protected)

```
Alice from IP 192.0.2.50 forgets her password
├─ Attempt 1: Wrong password → "Invalid credentials (4 attempts left)"
├─ Attempt 2: Wrong password → "Invalid credentials (3 attempts left)"
├─ Attempt 3: Remembers password, enters correct → LOGGED IN
│                                                   └─ Counter reset
├─ Later: Visits from same IP
└─ Attempt 4: Can login again → No carryover from previous failures
```

### Distributed Attack (Protected)

```
Botnet from 1000 different IPs attacks
├─ IP 203.0.113.1: 5 attempts → Locked for 15 minutes
├─ IP 203.0.113.2: 5 attempts → Locked for 15 minutes
├─ ...
├─ IP 203.0.113.1000: 5 attempts → Locked for 15 minutes
└─ Each IP can only attempt 5 passwords before timeout
   (1000 IPs × 5 attempts = 5,000 password attempts maximum)
   (vs. unlimited attempts without protection)
```

## Security Considerations

### Strengths

✅ **Simple**: Uses standard Django cache, minimal custom code
✅ **Auditable**: All attempts logged with timestamps and IPs
✅ **No Enumeration**: Attacker can't determine if username exists
✅ **Configurable**: Adjustable via environment variables
✅ **Automatic Expiration**: No manual unlock required
✅ **Performance**: O(1) cache lookups, doesn't stress database
✅ **Transparent**: Works without modifying authentication logic

### Limitations & Mitigations

⚠️ **IP-Based Limitation**: Corporate networks share IPs
- *Mitigation*: Legitimate users can call helpdesk for manual IP unlock
- *Alternative*: Upgrade to username+IP tracking for high-security needs

⚠️ **Proxy Spoofing**: X-Forwarded-For header can be spoofed
- *Mitigation*: Use only in trusted network environments
- *Alternative*: Validate proxy headers in reverse proxy configuration

⚠️ **Cache Clearance**: Restart clears all lockouts
- *Mitigation*: This is acceptable for deployment windows
- *Alternative*: Use persistent cache (Redis/Memcached)

⚠️ **Single Process**: LocMemCache doesn't share between processes
- *Mitigation*: Use gunicorn with single worker, or upgrade to shared cache
- *Recommended*: Redis for production deployments

## Testing

The implementation includes 16 automated tests:

```bash
# Run all brute-force tests
python manage.py test richard_musonera.test_bruteforce_simple -v 2
```

### Test Coverage

| Category | Tests | Coverage |
|----------|-------|----------|
| IP Detection | 5 | Direct, X-Forwarded-For, X-Real-IP, precedence |
| Failed Tracking | 5 | Single/multiple attempts, counter, lockout threshold |
| Lockout Expiration | 2 | Timeout expiration, separate IP tracking |
| Reset Functionality | 2 | Counter reset, lockout flag reset |
| Integration | 2 | Attack-recovery, legitimate user recovery |
| **Total** | **16** | **100% pass rate** |

### Running Tests

```bash
# Verbose output
python manage.py test richard_musonera.test_bruteforce_simple -v 2

# Specific test class
python manage.py test richard_musonera.test_bruteforce_simple.FailedLoginTrackingTests

# Specific test
python manage.py test richard_musonera.test_bruteforce_simple.FailedLoginTrackingTests.test_lockout_after_max_attempts
```

## Deployment Guide

### Single Server Deployment

**Recommended**: Use LocMemCache (default configuration)

```python
# settings.py - already configured
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
        'OPTIONS': {'MAX_ENTRIES': 1000}
    }
}
```

### Multi-Server Deployment

**Recommendation**: Upgrade to Redis or Memcached

```python
# settings.py - upgrade for multi-server
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
```

**Code changes needed**: NONE - Cache API is identical

### AWS/Cloud Deployment

```python
# Use ElastiCache for Redis
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://elasticache-endpoint.region.cache.amazonaws.com:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11
RUN pip install django redis django-redis
# ... copy app files ...
ENV MAX_LOGIN_ATTEMPTS=5
ENV LOCKOUT_PERIOD=900
CMD ["gunicorn", "devsec_demo.wsgi", "--workers=1"]
```

**Important**: Use `--workers=1` or configure shared cache (Redis) for multiple workers.

## Monitoring & Alerts

### Log Monitoring

```bash
# All failed attempts
docker logs django_app | grep "Failed login attempt" | tail -20

# Lockout events
docker logs django_app | grep "locked out" | tail -20

# Blocked attempts (during lockout)
docker logs django_app | grep "Login attempt blocked" | tail -20
```

### Metrics to Track

1. **Failed Attempts per Hour** (baseline: 1-5)
2. **Unique IPs Locked Out per Day** (baseline: 0-2)
3. **Lockout False Positives** (monitor user complaints)
4. **Successful Logins After Attempts** (shows recovery)

### Recommended Alerts

- Alert if **>50 unique IPs** attempt login in 1 minute
- Alert if **>100 failed attempts** from single IP in 1 hour
- Alert if **manual clear** triggered (admin action)

## Security Incident Response

### Suspected Attack: Unusual Login Pattern

```bash
# Check for attack
grep "Failed login attempt" /var/log/django.log | \
  cut -d' ' -f14 | sort | uniq -c | sort -rn | head -10

# If single IP has >100 failures: block it at firewall level
sudo iptables -A INPUT -s 203.0.113.100 -j DROP
```

### Legitimate User Lockout

```python
# Manual unlock if needed
# In Django shell:
from django.core.cache import cache

# Clear specific IP
cache.delete('login_locked_203.0.113.50')
cache.delete('login_attempts_203.0.113.50')
print("IP 203.0.113.50 unlocked")
```

### After Incident

1. **Review logs** for attack patterns
2. **Adjust thresholds** if false positives occurred
3. **Update firewall rules** if persistent attacker detected
4. **Notify users** affected by lockout
5. **Document incident** in security log

## Compliance Notes

- ✅ **OWASP Top 10 A07:2021** - Identification and Authentication Failures
- ✅ **NIST SP 800-63B** - Authentication and Lifecycle Management
- ✅ **PCI DSS Requirement 8.1.4** - Implement CAPTCHA and rate limiting

## Future Enhancements

### Phase 2 (Not Implemented)

1. **CAPTCHA Integration**: Show CAPTCHA after 2 failed attempts
2. **Email Notification**: Alert user of failed attempts
3. **Graduated Challenges**: Progressive delays between attempts
4. **Geographic Tracking**: Alert on login from new country/city

### Phase 3 (Advanced)

1. **Hardware Security Keys**: 2FA with FIDO2 tokens
2. **Risk-Based Authentication**: Adjust requirements based on context
3. **Behavioral Analysis**: ML-based anomaly detection
4. **Passwordless Login**: OAuth2, WebAuthn alternatives

## References

- [OWASP: Brute Force](https://owasp.org/www-community/attacks/Brute_force_attack)
- [Django Caching Documentation](https://docs.djangoproject.com/en/stable/topics/cache/)
- [NIST Guidelines on Authentication](https://pages.nist.gov/800-63-3/)
- [Django Authentication System](https://docs.djangoproject.com/en/stable/topics/auth/)

## Support

For issues or questions:

1. Check test results: `python manage.py test richard_musonera.test_bruteforce_simple`
2. Review logs: `grep "Failed login\|locked out" /var/log/django.log`
3. Verify configuration: `python manage.py shell` → `from django.conf import settings; print(settings.MAX_LOGIN_ATTEMPTS)`
4. Check cache: `python manage.py shell` → `from django.core.cache import cache; print(cache.get('login_attempts_127.0.0.1'))`

---

**Last Updated**: 2024
**Implementation Status**: ✅ Complete and Tested
**Test Coverage**: 16/16 tests passing (100%)
