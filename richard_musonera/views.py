from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.models import Group
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden

from .forms import (
    RegisterForm,
    LoginForm,
    PasswordChangeForm,
    UserProfileForm
)
from .rbac import role_required, admin_required


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