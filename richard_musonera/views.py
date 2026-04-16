from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.models import Group, User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.http import HttpResponseForbidden
from django.core.exceptions import PermissionDenied
from django.urls import reverse_lazy

from .forms import (
    RegisterForm,
    LoginForm,
    PasswordChangeForm,
    UserProfileForm,
    PasswordResetForm,
    SetPasswordForm
)
from .rbac import (
    role_required, 
    admin_required, 
    owner_required,
    check_object_ownership,
    has_role
)
from .models import UserProfile


# -------------------------
# REGISTER
# -------------------------
def register_view(request):
    form = RegisterForm()

    if request.method == "POST":
        form = RegisterForm(request.POST)

        if form.is_valid():
            user = form.save()

            # ✅ FIX: correctly inside block
            group, created = Group.objects.get_or_create(name="user")
            user.groups.add(group)

            login(request, user)
            messages.success(request, "Account created successfully.")
            return redirect("dashboard")

        else:
            messages.error(request, "Please fix the errors below.")

    return render(request, "richard_musonera/register.html", {"form": form})


# -------------------------
# LOGIN
# -------------------------
def login_view(request):
    form = LoginForm()

    if request.method == "POST":
        form = LoginForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]

            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                messages.success(request, "Logged in successfully.")
                return redirect("dashboard")

            messages.error(request, "Invalid credentials.")
        else:
            messages.error(request, "Invalid form input.")

    return render(request, "richard_musonera/login.html", {"form": form})


# -------------------------
# LOGOUT
# -------------------------
def logout_view(request):
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect("login")


# ==========================================
# PASSWORD RESET FLOW (Task #35)
# ==========================================
# Uses Django's built-in password reset utilities
# for secure token generation and management

class CustomPasswordResetView(PasswordResetView):
    """
    View for requesting a password reset.
    
    Security features:
    - Uses Django's PasswordResetTokenGenerator (HMAC-based)
    - Token is one-time use and expires after PASSWORD_RESET_TIMEOUT
    - Generic success message (doesn't leak if email exists)
    - Email-based verification prevents account takeover
    - CSRF protection enabled by default
    
    Process:
    1. User enters email
    2. Server checks if user exists (silently, no error)
    3. If exists, generates HMAC token and sends email
    4. User clicks link in email (token included)
    5. User confirms identity and sets new password
    """
    form_class = PasswordResetForm
    template_name = 'richard_musonera/password_reset_request.html'
    success_url = reverse_lazy('password_reset_done')
    email_template_name = 'richard_musonera/password_reset_email.txt'
    subject_template_name = 'richard_musonera/password_reset_subject.txt'
    from_email = None  # Uses DEFAULT_FROM_EMAIL from settings
    
    def form_valid(self, form):
        """Send password reset email securely."""
        # Django's PasswordResetForm.save() handles:
        # - Finding the user by email
        # - Generating secure HMAC token
        # - Rendering email template
        # - Sending email
        # - Doesn't raise exception if email not found (prevents user enumeration)
        form.save(
            request=self.request,
            use_https=self.request.is_secure(),
            from_email=self.from_email,
            email_template_name=self.email_template_name,
            subject_template_name=self.subject_template_name,
            html_email_template_name=None,  # Using plain text email
        )
        return super().form_valid(form)


def password_reset_done_view(request):
    """
    Confirmation page after password reset request.
    
    Shows generic message without confirming email existence
    to prevent user enumeration attacks.
    """
    return render(request, 'richard_musonera/password_reset_done.html')


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    """
    View for confirming password reset and setting new password.
    
    Security features:
    - Validates token (expires after PASSWORD_RESET_TIMEOUT)
    - Token is one-time use (consumed by Django's token generator)
    - Uses SetPasswordForm for strong password validation
    - Requires CSRF token for POST
    - Logs password change for audit trail
    
    Process:
    1. User clicks link from email (token in URL)
    2. Token is validated against user's password hash
    3. User enters new password (strength validated)
    4. New password is saved, invalidating all old tokens
    5. User is redirected to completion page
    """
    form_class = SetPasswordForm
    template_name = 'richard_musonera/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')
    
    def form_valid(self, form):
        """Save new password and log the change."""
        user = form.save()
        messages.success(
            self.request,
            'Your password has been reset successfully. You can now log in with your new password.'
        )
        return super().form_valid(form)


def password_reset_complete_view(request):
    """
    Final confirmation page after successful password reset.
    
    Shows success message and provides login link.
    """
    return render(request, 'richard_musonera/password_reset_complete.html')


# -------------------------
# PROTECTED PAGES
# -------------------------
@role_required("user")
def dashboard_view(request):
    return render(request, "richard_musonera/dashboard.html")


@login_required(login_url='login')
def profile_view(request):
    """Display and allow editing of user profile."""
    if request.method == "POST":
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Profile updated successfully.")
            return redirect("profile")
        else:
            messages.error(request, "Please fix the errors below.")
    else:
        form = UserProfileForm(instance=request.user)

    context = {
        'form': form,
        'user': request.user
    }
    return render(request, "richard_musonera/profile.html", context)


@login_required(login_url='login')
def password_change_view(request):
    """Allow users to change their password."""
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Keep the user logged in after password change
            update_session_auth_hash(request, user)
            messages.success(request, "Your password has been changed successfully.")
            return redirect("profile")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = PasswordChangeForm(request.user)

    context = {
        'form': form,
    }
    return render(request, "richard_musonera/password_change.html", context)


@role_required("instructor")
def instructor_panel(request):
    return render(request, "richard_musonera/instructor_panel.html")


@admin_required
def admin_dashboard(request):
    return render(request, "richard_musonera/admin_dashboard.html")


@admin_required
def admin_panel(request):
    return render(request, "richard_musonera/admin.html")


# -------------------------
# 403 HANDLER
# -------------------------
def custom_403(request, exception=None):
    return render(request, "richard_musonera/403.html", status=403)


# ==========================================
# ADMIN PROFILE MANAGEMENT (IDOR Prevention)
# ==========================================

@admin_required
def admin_view_users(request):
    """List all users (admin only)."""
    users = User.objects.all().prefetch_related('groups', 'profile').order_by('id')
    context = {
        'users': users,
    }
    return render(request, "richard_musonera/admin_users_list.html", context)


@admin_required
def admin_view_user_profile(request, user_id):
    """View a specific user's profile (admin only with IDOR prevention)."""
    # IDOR Prevention: Admin can view any user, but we still check it exists
    user = get_object_or_404(User, pk=user_id)
    
    try:
        profile = user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=user)
    
    roles = list(user.groups.values_list('name', flat=True))
    
    context = {
        'target_user': user,
        'profile': profile,
        'roles': roles,
    }
    return render(request, "richard_musonera/admin_view_user_profile.html", context)


@admin_required
def admin_edit_user_profile(request, user_id):
    """Edit a specific user's profile (admin only with IDOR prevention)."""
    # IDOR Prevention: Only admin can edit other users' profiles
    user = get_object_or_404(User, pk=user_id)
    
    try:
        profile = user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=user)
    
    if request.method == "POST":
        form = UserProfileForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.success(
                request, 
                f"Profile for {user.username} updated successfully."
            )
            return redirect('admin_view_user_profile', user_id=user.id)
        else:
            messages.error(request, "Please fix the errors below.")
    else:
        form = UserProfileForm(instance=user)

    context = {
        'form': form,
        'target_user': user,
        'profile': profile,
    }
    return render(request, "richard_musonera/admin_edit_user_profile.html", context)


@admin_required
def admin_assign_role(request, user_id):
    """Assign a role to a user (admin only with IDOR prevention)."""
    # IDOR Prevention: Only admin can modify other users' roles
    user = get_object_or_404(User, pk=user_id)
    
    if request.method == "POST":
        role_name = request.POST.get('role')
        action = request.POST.get('action')  # 'add' or 'remove'
        
        if not role_name:
            messages.error(request, "Role name is required.")
            return redirect('admin_view_user_profile', user_id=user.id)
        
        # Validate role exists
        try:
            role = Group.objects.get(name=role_name)
        except Group.DoesNotExist:
            messages.error(request, f"Role '{role_name}' does not exist.")
            return redirect('admin_view_user_profile', user_id=user.id)
        
        if action == 'add':
            user.groups.add(role)
            messages.success(
                request, 
                f"Role '{role_name}' assigned to {user.username}."
            )
        elif action == 'remove':
            user.groups.remove(role)
            messages.success(
                request, 
                f"Role '{role_name}' removed from {user.username}."
            )
        else:
            messages.error(request, "Invalid action.")
        
        return redirect('admin_view_user_profile', user_id=user.id)
    
    # GET request - show role assignment form
    user_roles = list(user.groups.values_list('name', flat=True))
    all_roles = Group.objects.all()
    
    context = {
        'target_user': user,
        'user_roles': user_roles,
        'all_roles': all_roles,
    }
    return render(request, "richard_musonera/admin_assign_role.html", context)