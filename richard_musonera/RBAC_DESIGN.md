# Role-Based Access Control (RBAC) Design Document

## Authorization Model Overview

The User Authentication Service uses **Django Groups** for role-based access control, providing a clean, Django-native approach to authorization that separates **authentication** (verifying who you are) from **authorization** (what you can do).

## Role Hierarchy

### 1. Anonymous Users (Not Authenticated)
**Definition**: Users who have not logged in.

**Allowed Actions**:
- View login page
- Register for new account
- View public pages (if any)

**Denied Actions**:
- Access dashboard
- View/edit profile
- Access protected areas
- Perform privileged operations

**HTTP Status**: 403 Forbidden (via Django's PermissionDenied exception)

---

### 2. Authenticated Users (Role: "user")
**Definition**: Users with a valid account who have logged in.

**Automatic Assignment**: All new users are automatically assigned to this role upon registration.

**Allowed Actions**:
- View their own dashboard
- View and edit their profile
- Change their password
- Logout
- Access basic user features

**Denied Actions**:
- Access admin panel
- Access instructor panel
- Modify other users' profiles
- Perform administrative tasks

**HTTP Status**: 403 Forbidden if attempting unauthorized access

---

### 3. Instructor Role
**Definition**: Staff or instructors who need to manage courses/content.

**Assignment**: Manually assigned by administrators via Django admin panel.

**Allowed Actions**:
- All "user" role permissions
- Access instructor panel
- View course management features
- Manage student submissions

**Example Group Name**: `instructor`

**Denied Actions**:
- Access admin panel
- Modify system settings
- User management

---

### 4. Admin Role
**Definition**: System administrators with full control.

**Assignment**: Manually assigned by superusers via Django admin panel.

**Allowed Actions**:
- All "user" and "instructor" permissions
- Access admin panel (`/admin/`, `/admin-panel/`)
- Manage users and roles
- System configuration
- View all user profiles

**Example Group Name**: `admin`

---

## Implementation Strategy

### A. Django Groups
The system uses **Django's built-in Groups** model from `django.contrib.auth`:

```python
from django.contrib.auth.models import Group

# Create roles
user_group, _ = Group.objects.get_or_create(name="user")
instructor_group, _ = Group.objects.get_or_create(name="instructor")
admin_group, _ = Group.objects.get_or_create(name="admin")

# Assign role to user
user.groups.add(user_group)

# Check if user has role
user.groups.filter(name="admin").exists()
```

### B. RBAC Decorators
Two custom decorators enforce authorization:

#### `@role_required(role_name)` or `@role_required([role1, role2])`
Checks if user has one of the specified roles:

```python
@role_required("user")
def dashboard_view(request):
    """Only authenticated users with 'user' role can access."""
    return render(request, "richard_musonera/dashboard.html")

@role_required(["admin", "instructor"])
def panel_view(request):
    """Users must have admin OR instructor role."""
    return render(request, "richard_musonera/admin.html")
```

#### `@admin_required`
Shorthand for `@role_required("admin")`:

```python
@admin_required
def admin_dashboard(request):
    """Only admins can access."""
    return render(request, "richard_musonera/admin_dashboard.html")
```

### C. Error Handling
Unauthorized access raises `PermissionDenied` exception, which triggers:
1. Django's built-in 403 handler
2. Custom 403.html template
3. User-friendly error message

```python
from django.core.exceptions import PermissionDenied

if user not authenticated or lacks required role:
    raise PermissionDenied()  # Renders 403.html
```

---

## Access Control Matrix

| Route | Anonymous | User | Instructor | Admin |
|-------|-----------|------|------------|-------|
| `/register/` | ✅ | ✅ | ✅ | ✅ |
| `/login/` | ✅ | ✅ | ✅ | ✅ |
| `/logout/` | ❌ | ✅ | ✅ | ✅ |
| `/dashboard/` | ❌ | ✅ | ✅ | ✅ |
| `/profile/` | ❌ | ✅ | ✅ | ✅ |
| `/change-password/` | ❌ | ✅ | ✅ | ✅ |
| `/instructor-panel/` | ❌ | ❌ | ✅ | ❌ |
| `/admin-panel/` | ❌ | ❌ | ❌ | ✅ |
| `/admin/` | ❌ | ❌ | ❌ | ✅ |

---

## Security Principles

### 1. Least Privilege
Users get minimum necessary permissions. New users only get "user" role; elevated roles require explicit admin assignment.

### 2. Separation of Concerns
- Authentication (is user logged in?) → Django's auth system
- Authorization (can user do X?) → Groups and custom decorators

### 3. Defense in Depth
- View-level protection via decorators
- URL routing validation
- Database-level permissions (via Django admin)
- Template-level hints (hiding UI elements in templates)

### 4. Fail Secure
- Invalid roles → 403 Forbidden (deny access)
- Failed group lookup → PermissionDenied
- Missing authentication → PermissionDenied

### 5. Auditable
- Group assignments visible in Django admin
- User-group relationships logged in database
- Authorization checks use standard Django exceptions

---

## Setup and Initialization

### Create Roles
```bash
python manage.py create_roles
```

This command creates three groups:
- `user`
- `instructor`
- `admin`

### Assign Roles
#### Via Django Admin:
1. Login to `/admin/`
2. Navigate to "Users"
3. Select a user
4. Scroll to "Groups"
5. Select roles to assign
6. Save

#### Programmatically:
```python
from django.contrib.auth.models import User, Group

user = User.objects.get(username='john')
admin_group = Group.objects.get(name='admin')
user.groups.add(admin_group)
user.save()
```

---

## Testing Strategy

### Test Coverage

**Authentication Tests**:
- ✅ Anonymous users cannot access protected pages
- ✅ Authenticated users can access allowed pages
- ✅ Invalid credentials rejected

**Authorization Tests**:
- ✅ User role cannot access admin panel
- ✅ Admin role can access admin panel
- ✅ Instructor role cannot access admin panel
- ✅ Multiple role combinations work correctly

**Error Handling Tests**:
- ✅ Unauthorized access returns 403
- ✅ 403.html template displays
- ✅ Users receive helpful error messages

### Example Test:
```python
def test_user_cannot_access_admin_panel(self):
    """Regular users lack admin role and should get 403."""
    self.client.login(username='user1', password='testpass123')
    response = self.client.get(reverse('admin_panel'))
    self.assertEqual(response.status_code, 403)

def test_admin_can_access_admin_panel(self):
    """Admins have the admin role and can access."""
    self.client.login(username='admin1', password='testpass123')
    response = self.client.get(reverse('admin_panel'))
    self.assertEqual(response.status_code, 200)
```

---

## Django Admin Integration

The system provides full admin integration:

**User Management**:
- Create/edit/delete users
- Manage group assignments
- View user profiles

**Group Management**:
- View all roles (groups)
- See which users have each role
- Add/remove users from roles

**UserProfile Admin**:
- Search by department, phone, email
- Filter by creation date
- Edit profile information inline

---

## Common Scenarios

### Scenario 1: New User Registration
1. User registers at `/register/`
2. Account created via `RegisterForm`
3. User automatically added to "user" group
4. `UserProfile` auto-created via signal
5. User redirected to dashboard
6. Only "user" role permissions apply

### Scenario 2: Promote User to Instructor
1. Admin logs into `/admin/`
2. Searches for user
3. Adds user to "instructor" group
4. Admin saves
5. Next time instructor logs in, they can access `/instructor-panel/`
6. Existing "user" role permissions still apply

### Scenario 3: Unauthorized Access Attempt
1. Regular user tries to access `/admin-panel/`
2. `@admin_required` decorator checks groups
3. User not in "admin" group
4. `PermissionDenied` raised
5. Django renders `403.html`
6. User sees "Access Denied" page

---

## Best Practices

### DO:
- ✅ Use `@role_required()` decorator on protected views
- ✅ Check groups in views before sensitive operations
- ✅ Assign roles via Django admin
- ✅ Log authorization checks for audit trail
- ✅ Document role requirements in code comments
- ✅ Test both allowed and denied paths
- ✅ Use `PermissionDenied` for policy violations

### DON'T:
- ❌ Hardcode user IDs for access control
- ❌ Mix authentication and authorization
- ❌ Trust user input for role determination
- ❌ Allow users to self-assign roles
- ❌ Use only `@login_required` for sensitive operations
- ❌ Hide features without enforcing permissions
- ❌ Grant roles via URL parameters

---

## Future Enhancements

1. **Per-Object Permissions**: Control access to specific objects (e.g., user can only edit their own profile)
2. **Fine-Grained Permissions**: Django's permission system for specific actions (=ADD, CHANGE, DELETE)
3. **Role-Based Rate Limiting**: Different limits per role
4. **Audit Logging**: Track all authorization decisions
5. **JWT Tokens**: For API endpoints with role claims

---

## Compliance & Standards

This RBAC implementation follows:
- **OWASP Top 10**: Broken Access Control mitigation
- **Principle of Least Privilege**: Users get minimum needed permissions
- **Django Security Conventions**: Uses built-in auth/groups
- **Defense in Depth**: Multiple layers of authorization
- **NIST Guidelines**: Role-based access control patterns

---

**Last Updated**: April 16, 2026  
**Version**: 1.0  
**Status**: Production Ready
