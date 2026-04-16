from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),

    # Password Reset (Task #35 - Secure Password Reset Flow)
    path("password-reset/", views.CustomPasswordResetView.as_view(), name="password_reset"),
    path("password-reset/done/", views.password_reset_done_view, name="password_reset_done"),
    path("password-reset/<uidb64>/<token>/", views.CustomPasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path("password-reset/complete/", views.password_reset_complete_view, name="password_reset_complete"),

    # User Account
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("profile/", views.profile_view, name="profile"),
    path("change-password/", views.password_change_view, name="password_change"),

    # Privileged
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("admin-panel/", views.admin_panel, name="admin_panel"),
    path("instructor-panel/", views.instructor_panel, name="instructor_panel"),
    
    # Admin Profile Management (IDOR Prevention - Task #34)
    path("admin/users/", views.admin_view_users, name="admin_view_users"),
    path("admin/users/<int:user_id>/", views.admin_view_user_profile, name="admin_view_user_profile"),
    path("admin/users/<int:user_id>/edit/", views.admin_edit_user_profile, name="admin_edit_user_profile"),
    path("admin/users/<int:user_id>/assign-role/", views.admin_assign_role, name="admin_assign_role"),
]