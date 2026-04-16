from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.models import Group, User
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.core.exceptions import PermissionDenied

from .forms import (
    RegisterForm,
    LoginForm,
    PasswordChangeForm,
    UserProfileForm
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