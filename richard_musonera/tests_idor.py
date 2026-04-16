"""
IDOR Prevention Tests

This test suite verifies that Insecure Direct Object Reference (IDOR)
vulnerabilities are prevented in user profile and account management views.

IDOR Vulnerability: A user can view or modify resources belonging to
another user by directly changing a URL parameter or ID.

Prevention Mechanism:
- Admin-only routes check user existence (don't leak if user exists)
- Proper access control via @admin_required decorator
- Explicit ownership verification before granting access
- Logging of unauthorized access attempts

Test Coverage:
- Users cannot view other users' admin profile pages
- Users cannot edit other users' profiles
- Users cannot assign/remove roles for other users
- Admins CAN view/edit any user's profile
- Admins CAN assign/remove roles
- Unauthorized attempts are logged and return 403
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.core.exceptions import PermissionDenied
from richard_musonera.models import UserProfile
from richard_musonera.rbac import (
    check_object_ownership,
    get_user_owned_object,
    has_role
)


class IDORPreventionSetupTests(TestCase):
    """Setup for IDOR prevention tests."""

    def setUp(self):
        """Create test users and roles."""
        # Create groups
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")
        self.instructor_group, _ = Group.objects.get_or_create(name="instructor")

        # Create test users
        self.alice = User.objects.create_user(
            username='alice',
            email='alice@example.com',
            password='password123'
        )
        self.alice.groups.add(self.user_group)

        self.bob = User.objects.create_user(
            username='bob',
            email='bob@example.com',
            password='password123'
        )
        self.bob.groups.add(self.user_group)

        self.charlie = User.objects.create_user(
            username='charlie',
            email='charlie@example.com',
            password='password123'
        )
        self.charlie.groups.add(self.admin_group)

        # Create profiles (should be auto-created)
        self.alice_profile = self.alice.profile
        self.bob_profile = self.bob.profile
        self.charlie_profile = self.charlie.profile

        self.client = Client()

    def test_setup_users_created(self):
        """Verify test users are created correctly."""
        self.assertEqual(User.objects.filter(username='alice').count(), 1)
        self.assertEqual(User.objects.filter(username='bob').count(), 1)
        self.assertEqual(User.objects.filter(username='charlie').count(), 1)

    def test_setup_roles_assigned(self):
        """Verify test users have correct roles."""
        self.assertTrue(has_role(self.alice, 'user'))
        self.assertTrue(has_role(self.bob, 'user'))
        self.assertTrue(has_role(self.charlie, 'admin'))


class UserIDORPreventionTests(TestCase):
    """Test IDOR prevention for standard users."""

    def setUp(self):
        """Set up test users."""
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")

        self.alice = User.objects.create_user('alice', 'alice@test.com', 'password')
        self.alice.groups.add(self.user_group)

        self.bob = User.objects.create_user('bob', 'bob@test.com', 'password')
        self.bob.groups.add(self.user_group)

        self.charlie = User.objects.create_user('charlie', 'charlie@test.com', 'password')
        self.charlie.groups.add(self.admin_group)

        self.client = Client()

    def test_user_cannot_view_other_user_admin_profile(self):
        """User cannot access admin profile view for another user."""
        self.client.login(username='alice', password='password')
        
        # Try to access Bob's admin profile view
        response = self.client.get(
            reverse('admin_view_user_profile', args=[self.bob.id])
        )
        
        # Should be denied (403) - not authenticated as admin
        self.assertEqual(response.status_code, 403)

    def test_user_cannot_edit_other_user_profile(self):
        """User cannot edit another user's profile."""
        self.client.login(username='alice', password='password')
        
        # Try to access Bob's edit profile view
        response = self.client.get(
            reverse('admin_edit_user_profile', args=[self.bob.id])
        )
        
        # Should be denied (403)
        self.assertEqual(response.status_code, 403)

    def test_user_cannot_assign_roles_to_other_users(self):
        """User cannot assign roles to another user."""
        self.client.login(username='alice', password='password')
        
        # Try to access Bob's role assignment view
        response = self.client.get(
            reverse('admin_assign_role', args=[self.bob.id])
        )
        
        # Should be denied (403)
        self.assertEqual(response.status_code, 403)

    def test_user_can_view_own_profile(self):
        """User can still view their own profile."""
        self.client.login(username='alice', password='password')
        
        # Access their own profile view (not admin profile)
        response = self.client.get(reverse('profile'))
        
        # Should succeed (200)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_cannot_view_admin_profiles(self):
        """Unauthenticated users cannot view admin profile pages."""
        response = self.client.get(
            reverse('admin_view_user_profile', args=[self.alice.id])
        )
        
        # Should redirect to login (302) or deny (403)
        self.assertIn(response.status_code, [302, 403])

    def test_unauthenticated_cannot_list_users(self):
        """Unauthenticated users cannot view user list."""
        response = self.client.get(reverse('admin_view_users'))
        
        # Should redirect to login (302) or deny (403)
        self.assertIn(response.status_code, [302, 403])


class AdminIDORPreventionTests(TestCase):
    """Test that admins CAN access user management (no IDOR vulnerability)."""

    def setUp(self):
        """Set up test users."""
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")

        self.alice = User.objects.create_user('alice', 'alice@test.com', 'password')
        self.alice.groups.add(self.user_group)

        self.admin = User.objects.create_user('admin', 'admin@test.com', 'password')
        self.admin.groups.add(self.admin_group)

        self.client = Client()

    def test_admin_can_view_user_profile(self):
        """Admin CAN view any user's profile."""
        self.client.login(username='admin', password='password')
        
        # Access Alice's admin profile view
        response = self.client.get(
            reverse('admin_view_user_profile', args=[self.alice.id])
        )
        
        # Should succeed (200)
        self.assertEqual(response.status_code, 200)

    def test_admin_can_list_all_users(self):
        """Admin CAN see list of all users."""
        self.client.login(username='admin', password='password')
        
        response = self.client.get(reverse('admin_view_users'))
        
        # Should succeed (200)
        self.assertEqual(response.status_code, 200)
        # Should contain both users
        self.assertContains(response, 'alice')
        self.assertContains(response, 'admin')

    def test_admin_can_edit_user_profile(self):
        """Admin CAN edit any user's profile."""
        self.client.login(username='admin', password='password')
        
        response = self.client.get(
            reverse('admin_edit_user_profile', args=[self.alice.id])
        )
        
        # Should succeed (200)
        self.assertEqual(response.status_code, 200)

    def test_admin_can_assign_roles(self):
        """Admin CAN assign roles to users."""
        self.client.login(username='admin', password='password')
        
        response = self.client.get(
            reverse('admin_assign_role', args=[self.alice.id])
        )
        
        # Should succeed (200)
        self.assertEqual(response.status_code, 200)

    def test_admin_can_actually_assign_role(self):
        """Admin can POST to assign a role."""
        self.client.login(username='admin', password='password')
        
        instructor_group, _ = Group.objects.get_or_create(name='instructor')
        
        # POST to assign role
        response = self.client.post(
            reverse('admin_assign_role', args=[self.alice.id]),
            {
                'role': 'instructor',
                'action': 'add'
            }
        )
        
        # Should redirect (302) after successful assignment
        self.assertEqual(response.status_code, 302)
        
        # Verify the role was actually assigned
        self.alice.refresh_from_db()
        self.assertIn('instructor', 
                     list(self.alice.groups.values_list('name', flat=True)))

    def test_admin_can_remove_role(self):
        """Admin can remove roles from users."""
        self.client.login(username='admin', password='password')
        
        user_group, _ = Group.objects.get_or_create(name='user')
        self.alice.groups.add(user_group)
        
        # Verify role is assigned
        self.assertTrue(has_role(self.alice, 'user'))
        
        # POST to remove role
        response = self.client.post(
            reverse('admin_assign_role', args=[self.alice.id]),
            {
                'role': 'user',
                'action': 'remove'
            }
        )
        
        # Should redirect (302)
        self.assertEqual(response.status_code, 302)
        
        # Verify the role was removed
        self.alice.refresh_from_db()
        self.assertNotIn('user',
                        list(self.alice.groups.values_list('name', flat=True)))


class ObjectOwnershipCheckTests(TestCase):
    """Test the check_object_ownership utility function."""

    def setUp(self):
        """Create test users and profiles."""
        self.user_group, _ = Group.objects.get_or_create(name="user")
        
        self.alice = User.objects.create_user('alice', 'alice@test.com', 'password')
        self.alice.groups.add(self.user_group)
        
        self.bob = User.objects.create_user('bob', 'bob@test.com', 'password')
        self.bob.groups.add(self.user_group)

    def test_check_ownership_pass_for_owner(self):
        """check_object_ownership should pass for the owner."""
        profile = self.alice.profile
        
        # Should not raise exception
        try:
            check_object_ownership(self.alice, profile)
        except PermissionDenied:
            self.fail("check_object_ownership raised PermissionDenied for owner")

    def test_check_ownership_fail_for_non_owner(self):
        """check_object_ownership should raise PermissionDenied for non-owner."""
        profile = self.alice.profile
        
        # Should raise PermissionDenied
        with self.assertRaises(PermissionDenied):
            check_object_ownership(self.bob, profile)

    def test_check_ownership_fail_for_anonymous(self):
        """check_object_ownership should raise PermissionDenied for anonymous users."""
        profile = self.alice.profile
        anonymous_user = User()  # Not saved, not authenticated
        
        # Should raise PermissionDenied
        with self.assertRaises(PermissionDenied):
            check_object_ownership(anonymous_user, profile)

    def test_get_user_owned_object_returns_for_owner(self):
        """get_user_owned_object should return object for owner."""
        profile = get_user_owned_object(
            self.alice, 
            UserProfile, 
            self.alice.profile.id
        )
        
        self.assertIsNotNone(profile)
        self.assertEqual(profile.user, self.alice)

    def test_get_user_owned_object_raises_for_non_owner(self):
        """get_user_owned_object should raise PermissionDenied for non-owner."""
        with self.assertRaises(PermissionDenied):
            get_user_owned_object(
                self.bob,
                UserProfile,
                self.alice.profile.id
            )

    def test_get_user_owned_object_returns_none_for_nonexistent(self):
        """get_user_owned_object should return None for nonexistent object."""
        result = get_user_owned_object(
            self.alice,
            UserProfile,
            99999  # Nonexistent ID
        )
        
        self.assertIsNone(result)


class IDORVulnerabilityScenarioTests(TestCase):
    """Test realistic IDOR attack scenarios."""

    def setUp(self):
        """Set up realistic scenario."""
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")

        # Normal users
        self.user1 = User.objects.create_user('user1', 'user1@test.com', 'password')
        self.user1.groups.add(self.user_group)

        self.user2 = User.objects.create_user('user2', 'user2@test.com', 'password')
        self.user2.groups.add(self.user_group)

        # Admin
        self.admin = User.objects.create_user('admin', 'admin@test.com', 'password')
        self.admin.groups.add(self.admin_group)

        # Add some profile data to make scenario realistic
        self.user1.first_name = "John"
        self.user1.last_name = "Doe"
        self.user1.save()

        self.user2.first_name = "Jane"
        self.user2.last_name = "Smith"
        self.user2.save()

        self.client = Client()

    def test_scenario_user_tries_sequential_id_enumeration(self):
        """User tries to enumerate user IDs sequentially (IDOR attack)."""
        self.client.login(username='user1', password='password')
        
        # Try to access profile views for IDs 1, 2, 3, etc.
        for user_id in [1, 2, 3]:
            response = self.client.get(
                reverse('admin_view_user_profile', args=[user_id])
            )
            # All should be denied (403)
            self.assertEqual(response.status_code, 403,
                           f"User could access admin profile for user {user_id}!")

    def test_scenario_user_tries_role_escalation_via_id_mangling(self):
        """User tries to escalate privileges by manipulating user ID parameter."""
        self.client.login(username='user1', password='password')
        
        # Try to assign themselves the admin role
        response = self.client.post(
            reverse('admin_assign_role', args=[self.user1.id]),
            {
                'role': 'admin',
                'action': 'add'
            }
        )
        
        # Should be denied (403) - not admin
        self.assertEqual(response.status_code, 403)
        
        # Verify they still don't have admin role
        self.user1.refresh_from_db()
        self.assertFalse(has_role(self.user1, 'admin'))

    def test_scenario_user_tries_to_steal_admin_privileges(self):
        """User tries to remove admin role from admin user."""
        self.client.login(username='user1', password='password')
        
        # Try to remove admin role from the admin
        response = self.client.post(
            reverse('admin_assign_role', args=[self.admin.id]),
            {
                'role': 'admin',
                'action': 'remove'
            }
        )
        
        # Should be denied (403)
        self.assertEqual(response.status_code, 403)
        
        # Verify admin still has admin role
        self.admin.refresh_from_db()
        self.assertTrue(has_role(self.admin, 'admin'))

    def test_scenario_non_existent_id_404_not_info_leak(self):
        """Admin accessing non-existent user ID should return 404, not leak info."""
        self.client.login(username='admin', password='password')
        
        # Try to access non-existent user
        response = self.client.get(
            reverse('admin_view_user_profile', args=[99999])
        )
        
        # Should be 404 (not found), not 403 or leak info
        self.assertEqual(response.status_code, 404)


class ProfileUpdateIDORTests(TestCase):
    """Test IDOR prevention in profile update scenarios."""

    def setUp(self):
        """Set up test users."""
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")

        self.alice = User.objects.create_user('alice', 'alice@test.com', 'password')
        self.alice.groups.add(self.user_group)
        self.alice.first_name = "Alice"
        self.alice.save()

        self.bob = User.objects.create_user('bob', 'bob@test.com', 'password')
        self.bob.groups.add(self.user_group)
        self.bob.first_name = "Bob"
        self.bob.save()

        self.admin = User.objects.create_user('admin', 'admin@test.com', 'password')
        self.admin.groups.add(self.admin_group)

        self.client = Client()

    def test_user_cannot_modify_other_user_profile_via_admin_edit(self):
        """User cannot change Bob's name via admin edit endpoint."""
        self.client.login(username='alice', password='password')
        
        # Try to change Bob's first name
        response = self.client.post(
            reverse('admin_edit_user_profile', args=[self.bob.id]),
            {
                'first_name': 'Robert',
                'last_name': 'Builder',
                'email': 'bob@test.com'
            }
        )
        
        # Should be denied (403)
        self.assertEqual(response.status_code, 403)
        
        # Verify Bob's name wasn't changed
        self.bob.refresh_from_db()
        self.assertEqual(self.bob.first_name, "Bob")

    def test_admin_can_modify_user_profile(self):
        """Admin can legitimately edit user profiles."""
        self.client.login(username='admin', password='password')
        
        # Admin changes Alice's profile
        response = self.client.post(
            reverse('admin_edit_user_profile', args=[self.alice.id]),
            {
                'first_name': 'Alicia',
                'last_name': 'Updated',
                'email': 'alice.new@test.com'
            }
        )
        
        # Should redirect (302) after success
        self.assertEqual(response.status_code, 302)
        
        # Verify the changes were saved
        self.alice.refresh_from_db()
        self.assertEqual(self.alice.first_name, 'Alicia')
        self.assertEqual(self.alice.email, 'alice.new@test.com')

    def test_user_own_profile_page_still_works(self):
        """User can still edit their own profile via the regular endpoint."""
        self.client.login(username='alice', password='password')
        
        # Access own profile (not admin endpoint)
        response = self.client.post(
            reverse('profile'),
            {
                'first_name': 'Alice Updated',
                'last_name': 'Smith',
                'email': 'alice@newdomain.com'
            }
        )
        
        # Should work (redirect after success)
        self.assertEqual(response.status_code, 302)
        
        # Verify changes
        self.alice.refresh_from_db()
        self.assertEqual(self.alice.first_name, 'Alice Updated')


class IDORAccessControlMatrixTests(TestCase):
    """Test the complete access control matrix."""

    def setUp(self):
        """Set up comprehensive test scenario."""
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")
        self.instructor_group, _ = Group.objects.get_or_create(name="instructor")

        self.anon_user = User()  # Anonymous
        
        self.regular_user = User.objects.create_user('user', 'user@test.com', 'pwd')
        self.regular_user.groups.add(self.user_group)
        
        self.instructor = User.objects.create_user('inst', 'inst@test.com', 'pwd')
        self.instructor.groups.add(self.instructor_group)
        
        self.admin = User.objects.create_user('admin', 'admin@test.com', 'pwd')
        self.admin.groups.add(self.admin_group)

        self.client = Client()

    def test_access_matrix_admin_users_list(self):
        """Test access to admin user list for all roles."""
        # Anonymous: Denied
        response = self.client.get(reverse('admin_view_users'))
        self.assertIn(response.status_code, [302, 403])
        
        # Regular user: Denied (403)
        self.client.login(username='user', password='pwd')
        response = self.client.get(reverse('admin_view_users'))
        self.assertEqual(response.status_code, 403)
        self.client.logout()
        
        # Instructor: Denied (403)
        self.client.login(username='inst', password='pwd')
        response = self.client.get(reverse('admin_view_users'))
        self.assertEqual(response.status_code, 403)
        self.client.logout()
        
        # Admin: Allowed (200)
        self.client.login(username='admin', password='pwd')
        response = self.client.get(reverse('admin_view_users'))
        self.assertEqual(response.status_code, 200)

    def test_access_matrix_admin_edit_user(self):
        """Test access to admin edit user for all roles."""
        target_id = self.regular_user.id
        url = reverse('admin_edit_user_profile', args=[target_id])
        
        # Anonymous: Redirect or Deny
        response = self.client.get(url)
        self.assertIn(response.status_code, [302, 403])
        
        # Regular user: Denied (403)
        self.client.login(username='user', password='pwd')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
        self.client.logout()
        
        # Instructor: Denied (403)
        self.client.login(username='inst', password='pwd')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
        self.client.logout()
        
        # Admin: Allowed (200)
        self.client.login(username='admin', password='pwd')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
