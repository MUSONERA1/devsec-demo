from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import UserProfile


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
