# User Authentication Service (UAS) - The Richard Musonera App

## Overview

The **Richard Musonera User Authentication Service** is a comprehensive, production-ready Django authentication system with role-based access control (RBAC). It provides a complete authentication lifecycle including user registration, login, logout, password management, and profile management.

## Features

### Core Authentication
- **User Registration**: Self-service registration with email verification requirements
- **Login**: Secure login with username/password authentication
- **Logout**: Safe session termination
- **Password Change**: Secure password update functionality
- **Profile Management**: User profile creation and editing

### Role-Based Access Control (RBAC)
- **User Role**: Standard authenticated user with access to personal dashboard
- **Instructor Role**: Extended permissions for instructors
- **Admin Role**: Full system access for administrators
- **Decorator-Based Protection**: Easy-to-use Python decorators for view protection

### Security Features
- **CSRF Protection**: All forms protected with CSRF tokens
- **Password Validation**: Strong password requirements with built-in Django validators
- **Session Management**: Secure session handling with automatic profile creation
- **User Profile Model**: Extended user information with audit timestamps
- **Admin Integration**: Full Django admin support for user management

## Project Structure

```
richard_musonera/
├── models.py                    # UserProfile model with signal handlers
├── views.py                     # All authentication views
├── forms.py                     # Registration, login, password change forms
├── urls.py                      # URL routing configuration
├── admin.py                     # Admin panel configuration
├── rbac.py                      # Role-based access control decorators
├── tests.py                     # Comprehensive test suite
│
├── templates/richard_musonera/
│   ├── register.html            # Registration page
│   ├── login.html               # Login page
│   ├── dashboard.html           # User dashboard
│   ├── profile.html             # Profile view and edit
│   ├── password_change.html     # Password change form
│   ├── admin_dashboard.html     # Admin dashboard
│   ├── instructor_panel.html    # Instructor panel
│   └── 403.html                 # Access denied page
│
└── management/commands/
    └── create_roles.py          # Command to initialize roles
```

## Installation & Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Ensure your `requirements.txt` includes:
```
Django>=4.0
python-dotenv
```

### 2. Create Initial Roles

The system uses Django Groups to manage roles. Initialize them:

```bash
python manage.py create_roles
```

This command creates three groups:
- `user`: Standard authenticated users
- `instructor`: Instructors with extended permissions
- `admin`: System administrators

### 3. Apply Database Migrations

Since this app uses Django's built-in User model and a custom UserProfile model, run:

```bash
python manage.py migrate
```

### 4. Create a Superuser (Admin)

```bash
python manage.py createsuperuser
```

Follow the prompts to create an admin account.

### 5. Run Development Server

```bash
python manage.py runserver
```

The application will be available at `http://127.0.0.1:8000/`

## Usage

### Accessing the Application

**Public Routes** (no authentication required):
- `/register/` - User registration
- `/login/` - User login

**Protected Routes** (requires authentication):
- `/dashboard/` - User dashboard (role: user, instructor, admin)
- `/profile/` - User profile view/edit (authenticated users)
- `/change-password/` - Password change (authenticated users)
- `/instructor-panel/` - Instructor panel (role: instructor)
- `/admin-panel/` - Admin panel (role: admin)
- `/admin/` - Django admin panel (role: admin)

### User Registration Flow

1. Navigate to `http://localhost:8000/register/`
2. Fill in username, email, and password
3. Password must meet security requirements:
   - Minimum 8 characters
   - Cannot be purely numeric
   - Cannot be too similar to username
   - Cannot be a common password
4. Confirm password by entering it again
5. Click "Create Account"
6. User is automatically assigned to the 'user' group and logged in
7. Redirected to dashboard

### User Login Flow

1. Navigate to `http://localhost:8000/login/`
2. Enter username and password
3. Click "Login"
4. Upon success, redirected to dashboard
5. Session cookie is created with 2-week expiry (default Django setting)

### Password Change Flow

1. Log in and navigate to profile: `http://localhost:8000/profile/`
2. Click "Change Password"
3. Verify current password
4. Enter new password (must meet strength requirements)
5. Confirm new password
6. User remains logged in with new password (session preserved)

### Profile Management

1. Navigate to `/profile/` when logged in
2. View current profile information:
   - Username (read-only)
   - Email (read-only)
   - First name (editable)
   - Last name (editable)
   - Email (editable for updates)
   - Member since (read-only)
   - Last login (read-only)
3. Edit profile fields and click "Save Changes"
4. Access "Change Password" from this page

## Authentication Architecture

### Models

#### UserProfile
Extended user information automatically created for each new user:

```python
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True, max_length=500)
    avatar_url = models.URLField(blank=True)
    department = models.CharField(max_length=100, blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

### Forms

- **RegisterForm**: User registration with email field and password validation
- **LoginForm**: Username and password inputs
- **PasswordChangeForm**: Current password verification and new password confirmation
- **UserProfileForm**: First name, last name, and email editing

### Views

#### Public Views
- `register_view()`: Handles GET (form display) and POST (registration)
- `login_view()`: Handles GET (form display) and POST (authentication)

#### Protected Views
- `profile_view()`: Display and edit user profile (requires login)
- `password_change_view()`: Change password (requires login)
- `dashboard_view()`: User dashboard (requires 'user' role)
- `logout_view()`: Terminate session and redirect to login

#### Role-Restricted Views
- `instructor_panel()`: Requires 'instructor' role
- `admin_dashboard()`: Requires 'admin' role
- `admin_panel()`: Requires 'admin' role

### RBAC Implementation

Role-based access control uses Django Group permissions with decorators:

```python
@role_required("user")
def dashboard_view(request):
    return render(request, "richard_musonera/dashboard.html")

@role_required(["instructor", "admin"])  # Multiple roles supported
def instructor_panel(request):
    return render(request, "richard_musonera/instructor_panel.html")

@admin_required  # Shorthand for admin-only
def admin_panel(request):
    return render(request, "richard_musonera/admin.html")
```

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Required Auth | Description |
|--------|----------|---------------|-------------|
| GET | `/register/` | No | Registration form |
| POST | `/register/` | No | Create new user account |
| GET | `/login/` | No | Login form |
| POST | `/login/` | No | Authenticate user |
| GET | `/logout/` | Yes | Logout (clears session) |
| GET | `/dashboard/` | Yes (user) | User dashboard |
| GET | `/profile/` | Yes | User profile view |
| POST | `/profile/` | Yes | Update user profile |
| GET | `/change-password/` | Yes | Password change form |
| POST | `/change-password/` | Yes | Update password |
| GET | `/instructor-panel/` | Yes (instructor) | Instructor panel |
| GET | `/admin-panel/` | Yes (admin) | Admin panel |

## Error Handling

### Validation Errors
- Duplicate usernames are rejected
- Mismatched passwords show clear error messages
- Weak passwords are rejected with specific requirements
- Email validation ensures valid email format
- Invalid form data shows field-specific error messages

### Access Control Errors
- Unauthenticated users attempting protected routes: **403 Forbidden**
- Users without required roles: **403 Forbidden with custom error page**
- Custom 403 handler at `custom_403()` displays user-friendly error page

### Security Errors
- CSRF token missing: **403 Forbidden**
- Session expired: User redirected to login
- Invalid password on change: Error message with retry option

## Testing

The app includes comprehensive test coverage:

### Test Classes

1. **UserRegistrationTests**: Registration flow, validation, duplicate prevention
2. **UserLoginTests**: Login success, invalid credentials, session creation
3. **UserLogoutTests**: Session termination, redirects
4. **UserProfileTests**: Profile viewing, editing, validation
5. **PasswordChangeTests**: Password update, old password verification, session preservation
6. **RBACSecurityTests**: Role-based access control, permission enforcement
7. **CSRFProtectionTests**: CSRF token validation

### Running Tests

```bash
# Run all tests
python manage.py test richard_musonera

# Run specific test class
python manage.py test richard_musonera.tests.UserRegistrationTests

# Run with verbose output
python manage.py test richard_musonera -v 2

# Run tests with coverage
coverage run --source='richard_musonera' manage.py test richard_musonera
coverage report
```

### Test Coverage

- **Registration**: Success, duplicate username, password mismatch, weak password, missing email, profile auto-creation
- **Login**: Page load, success, invalid username, invalid password, session creation
- **Logout**: Session clearing, redirects
- **Profile**: Login requirement, data display, profile updates, email validation
- **Password Change**: Login requirement, success, wrong old password, mismatch, session preservation
- **RBAC**: Anonymous access denied, user role access, admin role access, instructor role access
- **CSRF**: Token validation on forms

## Security Best Practices Implemented

✅ **Password Security**
- Django's built-in password validators
- Minimum length enforcement
- Common password list checking
- Numeric-only password prevention
- User attribute similarity checking

✅ **CSRF Protection**
- All POST forms include `{% csrf_token %}`
- CSRF middleware enabled in settings
- Token validation on all form submissions

✅ **Session Security**
- Django's secure session framework
- HTTPS recommended in production
- Session timeout configurable
- Secure cookies recommended in production

✅ **Input Validation**
- Form validation on both client and server
- Email validation using Django validators
- URL validation for profile fields
- User input sanitized via template escaping

✅ **Authentication**
- Django's built-in authentication backend
- Passwords never stored in plaintext
- Argon2 hashing recommended (with Django-Argon2)
- Login session tracking

✅ **Authorization**
- Group-based role system
- Decorator-based view protection
- Custom 403 error handling
- Permission inheritance structure

✅ **Error Handling**
- User-friendly error messages
- No sensitive information in error messages
- Secure 403 error page
- SQL injection prevention via ORM

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```
DJANGO_SECRET_KEY=your-secret-key-here
DJANGO_DEBUG=False  # Set to False in production
ALLOWED_HOSTS=localhost,127.0.0.1,yourdomain.com
```

### Settings.py Integration

Already configured in `devsec_demo/settings.py`:

```python
INSTALLED_APPS = [
    # ...
    'richard_musonera',
]

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
```

## Admin Panel

Access Django admin at `/admin/` with superuser credentials.

### User Management
- View all registered users
- Manage user groups and permissions
- View user profiles
- Edit user information
- Manage UserProfile details (bio, department, phone)

### UserProfile Admin Features
- Search users by username, email, department, phone
- Filter by creation/update date
- View profile metadata (created_at, updated_at)
- Edit profile information in admin interface

## Production Deployment Checklist

- [ ] Set `DEBUG = False` in settings
- [ ] Set strong `SECRET_KEY` environment variable
- [ ] Configure `ALLOWED_HOSTS` for your domain
- [ ] Use HTTPS only
- [ ] Set `SECURE_SSL_REDIRECT = True`
- [ ] Enable `SECURE_HSTS_SECONDS`
- [ ] Set `SESSION_COOKIE_SECURE = True`
- [ ] Set `CSRF_COOKIE_SECURE = True`
- [ ] Configure email backend for password reset emails
- [ ] Set up proper logging
- [ ] Configure database backups
- [ ] Run `python manage.py check --deploy`

## Common Issues & Solutions

### Issue: "Account created successfully" but user not logged in
**Solution**: Check that user group assignment completed. Run `python manage.py create_roles`

### Issue: Password change logs user out
**Solution**: This is normal behavior if `update_session_auth_hash()` isn't called. Current implementation preserves session.

### Issue: 403 errors when accessing admin panel
**Solution**: Ensure user is assigned to 'admin' group. Use Django admin to add user to group.

### Issue: CSRF token mismatch on form submission
**Solution**: Ensure form includes `{% csrf_token %}` and CSRF middleware is enabled.

### Issue: Email validation failing
**Solution**: Check `.env` file email configuration. Simple validation built-in.

## Contributing

When modifying this authentication system:

1. Write tests for new features
2. Maintain CSRF protection on all forms
3. Use role_required() decorator for protected views
4. Document any new endpoints in this README
5. Follow Django security best practices
6. Test with `python manage.py check --deploy`

## Support & Documentation

- Django Documentation: https://docs.djangoproject.com/
- Django Security: https://docs.djangoproject.com/en/stable/topics/security/
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

## License

This project is part of the devsec-demo educational repository.

---

**Last Updated**: 2024
**Maintainer**: Security Education Team
