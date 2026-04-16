"""
Role-Based Access Control (RBAC) Authorization Tests

This test suite comprehensively covers the authorization model, ensuring that:
- Anonymous users are properly denied access
- Authenticated users can only access their allowed resources
- Privileged users (instructors, admins) can access their areas
- Unauthorized access attempts are safely handled
- Authorization checks work across views and routes

Test Strategy:
    1. Test each role's access to each route
    2. Verify both allowed and denied cases
    3. Check for proper HTTP status codes
    4. Ensure error pages render correctly
    5. Test role combination scenarios
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse


class RBACSetupTests(TestCase):
    """Test RBAC infrastructure and role initialization."""

    def setUp(self):
        """Initialize roles and test users."""
        self.client = Client()
        
        # Create roles
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")
        self.instructor_group, _ = Group.objects.get_or_create(name="instructor")

    def test_roles_created(self):
        """Verify that all required roles exist."""
        self.assertTrue(Group.objects.filter(name="user").exists())
        self.assertTrue(Group.objects.filter(name="admin").exists())
        self.assertTrue(Group.objects.filter(name="instructor").exists())

    def test_user_can_be_added_to_group(self):
        """Verify that users can be added to groups."""
        user = User.objects.create_user(username='testuser', password='pass123')
        user.groups.add(self.user_group)
        self.assertTrue(user.groups.filter(name='user').exists())

    def test_user_can_have_multiple_roles(self):
        """Verify that users can have multiple roles."""
        user = User.objects.create_user(username='testuser', password='pass123')
        user.groups.add(self.user_group)
        user.groups.add(self.instructor_group)
        
        user_roles = list(user.groups.values_list('name', flat=True))
        self.assertIn('user', user_roles)
        self.assertIn('instructor', user_roles)


class AnonymousUserAuthorizationTests(TestCase):
    """Test authorization for anonymous (unauthenticated) users."""

    def setUp(self):
        self.client = Client()

    def test_anonymous_denied_dashboard(self):
        """Anonymous users cannot access dashboard."""
        response = self.client.get(reverse('dashboard'), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_anonymous_denied_profile(self):
        """Anonymous users cannot access profile."""
        response = self.client.get(reverse('profile'), follow=True)
        # Profile uses @login_required, not @role_required
        # So it redirects to login, not 403
        self.assertIn(response.status_code, [302, 403])

    def test_anonymous_denied_admin_panel(self):
        """Anonymous users cannot access admin panel."""
        response = self.client.get(reverse('admin_panel'), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_anonymous_denied_instructor_panel(self):
        """Anonymous users cannot access instructor panel."""
        response = self.client.get(reverse('instructor_panel'), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_anonymous_can_access_login(self):
        """Anonymous users can access login page."""
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)

    def test_anonymous_can_access_register(self):
        """Anonymous users can access registration page."""
        response = self.client.get(reverse('register'))
        self.assertEqual(response.status_code, 200)

    def test_anonymous_gets_403_page(self):
        """Unauthorized access renders 403.html template."""
        response = self.client.get(reverse('admin_panel'), follow=True)
        self.assertIn(b'403', response.content)


class AuthenticatedUserAuthorizationTests(TestCase):
    """Test authorization for basic authenticated users."""

    def setUp(self):
        self.client = Client()
        
        # Create user role
        self.user_group, _ = Group.objects.get_or_create(name="user")
        
        # Create authenticated user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
        self.user.groups.add(self.user_group)

    def test_user_can_access_dashboard(self):
        """Users with 'user' role can access dashboard."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_user_can_access_profile(self):
        """Authenticated users can access their profile."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)

    def test_user_can_access_password_change(self):
        """Authenticated users can access password change."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(reverse('password_change'))
        self.assertEqual(response.status_code, 200)

    def test_user_denied_admin_panel(self):
        """Users without admin role cannot access admin panel."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(reverse('admin_panel'), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_user_denied_instructor_panel(self):
        """Users without instructor role cannot access instructor panel."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(reverse('instructor_panel'), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_user_can_logout(self):
        """Authenticated users can logout."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(reverse('logout'), follow=True)
        self.assertEqual(response.status_code, 200)
        # After logout, user is not authenticated
        # This could be verified by checking if subsequent protected access fails


class InstructorAuthorizationTests(TestCase):
    """Test authorization for instructors."""

    def setUp(self):
        self.client = Client()
        
        # Create roles
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.instructor_group, _ = Group.objects.get_or_create(name="instructor")
        
        # Create instructor user with both user and instructor roles
        self.instructor = User.objects.create_user(
            username='instructor1',
            email='instructor@example.com',
            password='InstructorPass123!'
        )
        self.instructor.groups.add(self.instructor_group)
        # Note: instructor might not have 'user' role by default

    def test_instructor_can_access_instructor_panel(self):
        """Users with instructor role can access instructor panel."""
        self.client.login(username='instructor1', password='InstructorPass123!')
        response = self.client.get(reverse('instructor_panel'))
        self.assertEqual(response.status_code, 200)

    def test_instructor_denied_admin_panel(self):
        """Instructors without admin role cannot access admin panel."""
        self.client.login(username='instructor1', password='InstructorPass123!')
        response = self.client.get(reverse('admin_panel'), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_instructor_can_access_dashboard_if_user_role(self):
        """Instructors with both roles can access dashboard."""
        # Add user role to instructor
        self.instructor.groups.add(self.user_group)
        
        self.client.login(username='instructor1', password='InstructorPass123!')
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_instructor_denied_dashboard_without_user_role(self):
        """Instructors without user role cannot access dashboard."""
        # Instructor doesn't have user role
        self.client.login(username='instructor1', password='InstructorPass123!')
        response = self.client.get(reverse('dashboard'), follow=True)
        self.assertEqual(response.status_code, 403)


class AdminAuthorizationTests(TestCase):
    """Test authorization for administrators."""

    def setUp(self):
        self.client = Client()
        
        # Create roles
        self.admin_group, _ = Group.objects.get_or_create(name="admin")
        
        # Create admin user
        self.admin = User.objects.create_user(
            username='admin1',
            email='admin@example.com',
            password='AdminPass123!'
        )
        self.admin.groups.add(self.admin_group)

    def test_admin_can_access_admin_panel(self):
        """Users with admin role can access admin panel."""
        self.client.login(username='admin1', password='AdminPass123!')
        response = self.client.get(reverse('admin_panel'))
        self.assertEqual(response.status_code, 200)

    def test_admin_can_access_django_admin(self):
        """Admins should be able to access Django admin (if staff)."""
        self.admin.is_staff = True
        self.admin.save()
        
        self.client.login(username='admin1', password='AdminPass123!')
        response = self.client.get(reverse('admin:index'))
        self.assertIn(response.status_code, [200, 301, 302])  # May redirect


class MultiRoleAuthorizationTests(TestCase):
    """Test authorization with multiple role combinations."""

    def setUp(self):
        self.client = Client()
        
        # Create roles
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.instructor_group, _ = Group.objects.get_or_create(name="instructor")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")

    def test_user_with_multiple_roles(self):
        """User with multiple roles can access all allowed areas."""
        user = User.objects.create_user(
            username='multiuser',
            password='MultiPass123!'
        )
        user.groups.add(self.user_group)
        user.groups.add(self.instructor_group)
        
        self.client.login(username='multiuser', password='MultiPass123!')
        
        # Should access user areas
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        
        # Should access instructor areas
        response = self.client.get(reverse('instructor_panel'))
        self.assertEqual(response.status_code, 200)
        
        # Should NOT access admin areas
        response = self.client.get(reverse('admin_panel'), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_admin_has_all_privileges(self):
        """Admin can access all privileged areas."""
        admin = User.objects.create_user(
            username='superadmin',
            password='SuperPass123!'
        )
        admin.groups.add(self.admin_group)
        
        self.client.login(username='superadmin', password='SuperPass123!')
        
        # Admin should be able to access admin areas
        response = self.client.get(reverse('admin_panel'))
        self.assertEqual(response.status_code, 200)


class RoleAssignmentTests(TestCase):
    """Test dynamic role assignment and permission updates."""

    def setUp(self):
        self.client = Client()
        
        # Create roles
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.instructor_group, _ = Group.objects.get_or_create(name="instructor")
        
        # Create user with only user role
        self.user = User.objects.create_user(
            username='testuser',
            password='TestPass123!'
        )
        self.user.groups.add(self.user_group)

    def test_permission_denied_before_role_assignment(self):
        """User cannot access instructor area before role assignment."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(reverse('instructor_panel'), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_permission_granted_after_role_assignment(self):
        """User can access instructor area after role assignment."""
        self.client.login(username='testuser', password='TestPass123!')
        
        # Before assignment
        response = self.client.get(reverse('instructor_panel'), follow=True)
        self.assertEqual(response.status_code, 403)
        
        # Assign instructor role
        self.user.groups.add(self.instructor_group)
        
        # After assignment (in same session)
        # Note: Django caches group membership, so logout/login for real test
        self.client.logout()
        self.client.login(username='testuser', password='TestPass123!')
        
        response = self.client.get(reverse('instructor_panel'))
        self.assertEqual(response.status_code, 200)

    def test_permission_removed_after_role_removal(self):
        """User loses access after role removal."""
        # Add instructor role
        self.user.groups.add(self.instructor_group)
        
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(reverse('instructor_panel'))
        self.assertEqual(response.status_code, 200)
        
        # Remove instructor role
        self.user.groups.remove(self.instructor_group)
        
        # Logout/login to refresh group cache
        self.client.logout()
        self.client.login(username='testuser', password='TestPass123!')
        
        # Should now be denied
        response = self.client.get(reverse('instructor_panel'), follow=True)
        self.assertEqual(response.status_code, 403)


class RBACUtilityFunctionTests(TestCase):
    """Test RBAC utility functions from rbac module."""

    def setUp(self):
        from richard_musonera.rbac import (
            has_role, has_any_role, has_all_roles, get_user_roles
        )
        
        self.has_role = has_role
        self.has_any_role = has_any_role
        self.has_all_roles = has_all_roles
        self.get_user_roles = get_user_roles
        
        # Create roles
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")
        self.instructor_group, _ = Group.objects.get_or_create(name="instructor")
        
        # Create test user
        self.user = User.objects.create_user(username='testuser', password='pass')
        self.user.groups.add(self.user_group)

    def test_has_role_with_existing_role(self):
        """has_role returns True for existing role."""
        self.assertTrue(self.has_role(self.user, 'user'))

    def test_has_role_with_missing_role(self):
        """has_role returns False for missing role."""
        self.assertFalse(self.has_role(self.user, 'admin'))

    def test_has_role_with_anonymous_user(self):
        """has_role returns False for anonymous users."""
        anon_user = User()  # Unsaved, not authenticated
        self.assertFalse(self.has_role(anon_user, 'user'))

    def test_has_any_role_with_one_match(self):
        """has_any_role returns True if user has at least one role."""
        self.assertTrue(self.has_any_role(self.user, ['user', 'admin']))

    def test_has_any_role_with_no_match(self):
        """has_any_role returns False if user has none of the roles."""
        self.assertFalse(self.has_any_role(self.user, ['admin', 'instructor']))

    def test_has_all_roles_with_single_role(self):
        """has_all_roles returns True if user has all specified roles."""
        self.assertTrue(self.has_all_roles(self.user, ['user']))

    def test_has_all_roles_with_multiple_roles_partial_match(self):
        """has_all_roles returns False if user lacks any role."""
        self.assertFalse(self.has_all_roles(self.user, ['user', 'admin']))

    def test_has_all_roles_with_multiple_roles_all_match(self):
        """has_all_roles returns True if user has all roles."""
        self.user.groups.add(self.admin_group)
        self.assertTrue(self.has_all_roles(self.user, ['user', 'admin']))

    def test_get_user_roles_returns_list(self):
        """get_user_roles returns list of role names."""
        roles = self.get_user_roles(self.user)
        self.assertIsInstance(roles, list)
        self.assertIn('user', roles)

    def test_get_user_roles_with_multiple_roles(self):
        """get_user_roles returns all roles for user."""
        self.user.groups.add(self.admin_group)
        self.user.groups.add(self.instructor_group)
        
        roles = self.get_user_roles(self.user)
        self.assertEqual(len(roles), 3)
        self.assertIn('user', roles)
        self.assertIn('admin', roles)
        self.assertIn('instructor', roles)

    def test_get_user_roles_with_anonymous_user(self):
        """get_user_roles returns empty list for anonymous users."""
        anon_user = User()
        roles = self.get_user_roles(anon_user)
        self.assertEqual(roles, [])
