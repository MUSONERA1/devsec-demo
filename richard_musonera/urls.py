from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),

    # User Account
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("profile/", views.profile_view, name="profile"),
    path("change-password/", views.password_change_view, name="password_change"),

    # Privileged
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("admin-panel/", views.admin_panel, name="admin_panel"),
    path("instructor-panel/", views.instructor_panel, name="instructor_panel"),
]