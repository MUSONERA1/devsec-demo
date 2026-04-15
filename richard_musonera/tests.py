from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.test.utils import override_settings
from .models import UserProfile


class UserRegistrationTests(TestCase):
    """Test user registration functionality."""

    def setUp(self):
        self.client = Client()
        self.register_url = reverse("register")

    def test_register_page_loads(self):
        """Test that registration page loads successfully."""
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "richard_musonera/register.html")

    def test_user_registration_success(self):
        """Test successful user registration."""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!'
        }
        response = self.client.post(self.register_url, data, follow=True)
        
        # Check user was created
        self.assertTrue(User.objects.filter(username='newuser').exists())
        user = User.objects.get(username='newuser')
        self.assertEqual(user.email, 'newuser@example.com')
        
        # Check user was automatically assigned to "user" group
        self.assertTrue(user.groups.filter(name='user').exists())

    def test_registration_duplicate_username(self):
        """Test that duplicate usernames are rejected."""
        User.objects.create_user(username='testuser', password='pass123')
        
        data = {
            'username': 'testuser',
            'email': 'newuser@example.com',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!'
        }
        response = self.client.post(self.register_url, data)
        self.assertFormError(response, 'form', 'username', 'A user with that username already exists.')

    def test_registration_password_mismatch(self):
        """Test that mismatched passwords are rejected."""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'SecurePass123!',
            'password2': 'DifferentPass123!'
        }
        response = self.client.post(self.register_url, data)
        self.assertTrue(response.context['form'].errors)

    def test_registration_weak_password(self):
        """Test that weak passwords are rejected."""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': '123',
            'password2': '123'
        }
        response = self.client.post(self.register_url, data)
        self.assertTrue(response.context['form'].errors)

    def test_registration_missing_email(self):
        """Test that email is required."""
        data = {
            'username': 'newuser',
            'email': '',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!'
        }
        response = self.client.post(self.register_url, data)
        self.assertFormError(response, 'form', 'email', 'This field is required.')

    def test_registered_user_has_profile(self):
        """Test that a UserProfile is automatically created for new users."""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!'
        }
        self.client.post(self.register_url, data)
        user = User.objects.get(username='newuser')
        self.assertTrue(hasattr(user, 'profile'))
        self.assertIsInstance(user.profile, UserProfile)


class UserLoginTests(TestCase):
    """Test user login functionality."""

    def setUp(self):
        self.client = Client()
        self.login_url = reverse("login")
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
        # Assign user to 'user' group
        user_group, _ = Group.objects.get_or_create(name='user')
        self.user.groups.add(user_group)

    def test_login_page_loads(self):
        """Test that login page loads successfully."""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "richard_musonera/login.html")

    def test_successful_login(self):
        """Test successful user login."""
        data = {
            'username': 'testuser',
            'password': 'TestPass123!'
        }
        response = self.client.post(self.login_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_login_invalid_username(self):
        """Test login with invalid username."""
        data = {
            'username': 'nonexistent',
            'password': 'TestPass123!'
        }
        response = self.client.post(self.login_url, data)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_login_invalid_password(self):
        """Test login with invalid password."""
        data = {
            'username': 'testuser',
            'password': 'WrongPassword123!'
        }
        response = self.client.post(self.login_url, data)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_login_creates_session(self):
        """Test that successful login creates a session."""
        data = {
            'username': 'testuser',
            'password': 'TestPass123!'
        }
        response = self.client.post(self.login_url, data, follow=True)
        self.assertIn('_auth_user_id', self.client.session)


class UserLogoutTests(TestCase):
    """Test user logout functionality."""

    def setUp(self):
        self.client = Client()
        self.logout_url = reverse("logout")
        self.user = User.objects.create_user(username='testuser', password='TestPass123!')
        user_group, _ = Group.objects.get_or_create(name='user')
        self.user.groups.add(user_group)

    def test_logout_view_exists(self):
        """Test that logout view exists."""
        response = self.client.get(self.logout_url, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_logout_clears_session(self):
        """Test that logout clears the user session."""
        self.client.login(username='testuser', password='TestPass123!')
        self.assertIn('_auth_user_id', self.client.session)
        
        response = self.client.get(self.logout_url, follow=True)
        self.assertNotIn('_auth_user_id', self.client.session)


class UserProfileTests(TestCase):
    """Test user profile functionality."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
        user_group, _ = Group.objects.get_or_create(name='user')
        self.user.groups.add(user_group)
        self.profile_url = reverse("profile")

    def test_profile_requires_login(self):
        """Test that profile page requires authentication."""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_authenticated_user_can_view_profile(self):
        """Test that authenticated user can view profile."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "richard_musonera/profile.html")

    def test_profile_shows_user_data(self):
        """Test that profile displays user information."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(self.profile_url)
        self.assertContains(response, 'testuser')

    def test_user_can_update_profile(self):
        """Test that user can update their profile."""
        self.client.login(username='testuser', password='TestPass123!')
        data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'newemail@example.com'
        }
        response = self.client.post(self.profile_url, data, follow=True)
        
        # Refresh user data
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'John')
        self.assertEqual(self.user.last_name, 'Doe')
        self.assertEqual(self.user.email, 'newemail@example.com')

    def test_profile_update_with_invalid_email(self):
        """Test that invalid email is rejected in profile update."""
        self.client.login(username='testuser', password='TestPass123!')
        data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'invalid-email'
        }
        response = self.client.post(self.profile_url, data)
        self.assertTrue(response.context['form'].errors)


class PasswordChangeTests(TestCase):
    """Test password change functionality."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPass123!'
        )
        user_group, _ = Group.objects.get_or_create(name='user')
        self.user.groups.add(user_group)
        self.password_change_url = reverse("password_change")

    def test_password_change_requires_login(self):
        """Test that password change page requires authentication."""
        response = self.client.get(self.password_change_url)
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_password_change_page_loads(self):
        """Test that password change page loads for authenticated user."""
        self.client.login(username='testuser', password='OldPass123!')
        response = self.client.get(self.password_change_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "richard_musonera/password_change.html")

    def test_password_change_success(self):
        """Test successful password change."""
        self.client.login(username='testuser', password='OldPass123!')
        data = {
            'old_password': 'OldPass123!',
            'new_password1': 'NewPass456!',
            'new_password2': 'NewPass456!'
        }
        response = self.client.post(self.password_change_url, data, follow=True)
        
        # Test that user can login with new password
        self.client.logout()
        login_success = self.client.login(username='testuser', password='NewPass456!')
        self.assertTrue(login_success)

    def test_password_change_wrong_old_password(self):
        """Test that wrong old password is rejected."""
        self.client.login(username='testuser', password='OldPass123!')
        data = {
            'old_password': 'WrongPassword123!',
            'new_password1': 'NewPass456!',
            'new_password2': 'NewPass456!'
        }
        response = self.client.post(self.password_change_url, data)
        self.assertTrue(response.context['form'].errors)

    def test_password_change_mismatch(self):
        """Test that mismatched new passwords are rejected."""
        self.client.login(username='testuser', password='OldPass123!')
        data = {
            'old_password': 'OldPass123!',
            'new_password1': 'NewPass456!',
            'new_password2': 'DifferentPass789!'
        }
        response = self.client.post(self.password_change_url, data)
        self.assertTrue(response.context['form'].errors)

    def test_password_change_keeps_user_logged_in(self):
        """Test that user remains logged in after password change."""
        self.client.login(username='testuser', password='OldPass123!')
        data = {
            'old_password': 'OldPass123!',
            'new_password1': 'NewPass456!',
            'new_password2': 'NewPass456!'
        }
        response = self.client.post(self.password_change_url, data, follow=True)
        self.assertTrue(response.wsgi_request.user.is_authenticated)


class RBACSecurityTests(TestCase):
    """Test role-based access control."""

    def setUp(self):
        self.client = Client()

        # Create groups
        self.user_group, _ = Group.objects.get_or_create(name="user")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")
        self.instructor_group, _ = Group.objects.get_or_create(name="instructor")

        # Create users
        self.user = User.objects.create_user(username="user1", password="testpass123")
        self.user.groups.add(self.user_group)

        self.admin = User.objects.create_user(username="admin1", password="testpass123")
        self.admin.groups.add(self.admin_group)

        self.instructor = User.objects.create_user(username="inst1", password="testpass123")
        self.instructor.groups.add(self.instructor_group)

    # -------------------------
    # ANONYMOUS ACCESS
    # -------------------------
    def test_anonymous_cannot_access_dashboard(self):
        """Test that unauthenticated users cannot access dashboard."""
        response = self.client.get(reverse("dashboard"), follow=True)
        # Should either be 403 or redirected
        self.assertIn(response.status_code, [403, 302])

    def test_anonymous_cannot_access_admin(self):
        """Test that unauthenticated users cannot access admin panel."""
        response = self.client.get(reverse("admin_panel"), follow=True)
        self.assertIn(response.status_code, [403, 302])

    def test_anonymous_can_access_login(self):
        """Test that unauthenticated users can access login page."""
        response = self.client.get(reverse("login"))
        self.assertEqual(response.status_code, 200)

    def test_anonymous_can_access_register(self):
        """Test that unauthenticated users can access registration page."""
        response = self.client.get(reverse("register"))
        self.assertEqual(response.status_code, 200)

    # -------------------------
    # USER ACCESS
    # -------------------------
    def test_user_can_access_dashboard(self):
        """Test that users with 'user' role can access dashboard."""
        self.client.login(username="user1", password="testpass123")
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_user_can_access_profile(self):
        """Test that users can access their profile."""
        self.client.login(username="user1", password="testpass123")
        response = self.client.get(reverse("profile"))
        self.assertEqual(response.status_code, 200)

    def test_user_cannot_access_admin_panel(self):
        """Test that regular users cannot access admin panel."""
        self.client.login(username="user1", password="testpass123")
        response = self.client.get(reverse("admin_panel"), follow=True)
        # Should get 403
        self.assertIn(response.status_code, [403, 302])

    def test_user_cannot_access_instructor_panel(self):
        """Test that regular users cannot access instructor panel."""
        self.client.login(username="user1", password="testpass123")
        response = self.client.get(reverse("instructor_panel"), follow=True)
        self.assertIn(response.status_code, [403, 302])

    # -------------------------
    # ADMIN ACCESS
    # -------------------------
    def test_admin_can_access_admin_panel(self):
        """Test that admins can access admin panel."""
        self.client.login(username="admin1", password="testpass123")
        response = self.client.get(reverse("admin_panel"))
        self.assertEqual(response.status_code, 200)

    def test_admin_can_access_dashboard(self):
        """Test that admins can access dashboard."""
        self.client.login(username="admin1", password="testpass123")
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_admin_cannot_access_instructor_panel(self):
        """Test that admins (without instructor role) cannot access instructor panel."""
        self.client.login(username="admin1", password="testpass123")
        response = self.client.get(reverse("instructor_panel"), follow=True)
        self.assertIn(response.status_code, [403, 302])

    # -------------------------
    # INSTRUCTOR ACCESS
    # -------------------------
    def test_instructor_can_access_panel(self):
        """Test that instructors can access instructor panel."""
        self.client.login(username="inst1", password="testpass123")
        response = self.client.get(reverse("instructor_panel"))
        self.assertEqual(response.status_code, 200)

    def test_instructor_can_access_dashboard(self):
        """Test that instructors with 'user' role can access dashboard."""
        self.instructor.groups.add(self.user_group)
        self.client.login(username="inst1", password="testpass123")
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_instructor_cannot_access_admin_panel(self):
        """Test that instructors cannot access admin panel."""
        self.client.login(username="inst1", password="testpass123")
        response = self.client.get(reverse("admin_panel"), follow=True)
        self.assertIn(response.status_code, [403, 302])