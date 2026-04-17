from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import UserProfile, AuditLog


class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile within User admin."""
    model = UserProfile
    fields = ('bio', 'avatar_url', 'department', 'phone_number', 'created_at', 'updated_at')
    readonly_fields = ('created_at', 'updated_at')
    can_delete = False


class UserAdmin(BaseUserAdmin):
    """Extended User admin with UserProfile inline."""
    inlines = [UserProfileInline]


# Unregister the original User admin and register the new one
admin.site.unregister(User)
admin.site.register(User, UserAdmin)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for UserProfile model."""
    list_display = ('user', 'department', 'phone_number', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at', 'department')
    search_fields = ('user__username', 'user__email', 'department', 'phone_number')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Profile Details', {
            'fields': ('bio', 'department', 'phone_number', 'avatar_url')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin interface for security audit logs."""
    
    list_display = ('event_type', 'user', 'target_user', 'success', 'timestamp', 'ip_address')
    list_filter = ('event_type', 'success', 'timestamp')
    search_fields = ('user__username', 'target_user__username', 'ip_address', 'event_details')
    readonly_fields = ('timestamp', 'event_details', 'user_agent')
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Event Information', {
            'fields': ('event_type', 'timestamp', 'success')
        }),
        ('Users', {
            'fields': ('user', 'target_user')
        }),
        ('Request Information', {
            'fields': ('ip_address', 'user_agent'),
            'classes': ('collapse',)
        }),
        ('Event Details', {
            'fields': ('event_details',),
            'classes': ('collapse',)
        }),
        ('Error Information', {
            'fields': ('error_description',),
            'classes': ('collapse',)
        }),
    )
    
    def has_add_permission(self, request):
        """Prevent manual creation of audit logs in admin."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of audit logs (audit trail integrity)."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Prevent modification of audit logs (audit trail integrity)."""
        return False
