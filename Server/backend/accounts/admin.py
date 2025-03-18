from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from accounts.models import CustomUser, UserProfile


class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile to display/edit alongside CustomUser."""
    model = UserProfile
    can_delete = False  # Prevent deletion of profiles independently
    verbose_name_plural = "Profile"  # Singular since it's one-to-one
    fields = [
        'image', 'description', 'department', 'job_title', 'time_zone', 'preferences',
        'last_login_ip', 'logon_count', 'locked_out', 'lockout_time', 'enabled',
        'account_expires', 'password_expires', 'password_last_set', 'last_logon',
        'user_may_change_password', 'password_required', 'password_changeable_date',
        'principal_source', 'object_class', 'local_groups'
    ]
    readonly_fields = ['last_login_ip', 'logon_count', 'last_logon']  # Auto-updated fields


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """Custom admin for CustomUser model with tailored fields and filters."""
    # Override BaseUserAdmin fields to match CustomUser
    fieldsets = (
        (None, {'fields': ('sid', 'password')}),
        ('Personal Info', {'fields': ('full_name', 'email')}),
        ('Windows Info', {'fields': ('sid_type', 'domain', 'local_account', 'account_type', 'caption', 'status')}),
        ('System Info', {'fields': ('is_shutting_down', 'password_changed')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('sid', 'email', 'password1', 'password2', 'full_name', 'domain'),
        }),
    )

    # Display and filtering options
    list_display = ('sid', 'email', 'full_name', 'domain', 'is_active', 'created_at', 'last_login')
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'local_account', 'domain', 'created_at')
    search_fields = ('sid', 'email', 'full_name', 'domain', 'caption')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at', 'sid_type', 'caption')  # Auto-populated fields

    # Inline UserProfile
    inlines = [UserProfileInline]

    # Customize for SID-based auth
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if not obj:  # Only for adding new users
            form.base_fields['sid'].help_text = "Enter the user's Windows SID (e.g., S-1-5-21-123-456-789-1001)"
        return form

    def has_change_permission(self, request, obj=None):
        """Restrict changing SID after creation."""
        if obj and request.user.is_superuser:
            return True
        return super().has_change_permission(request, obj)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for standalone UserProfile management."""
    list_display = ('user_sid', 'department', 'job_title', 'last_logon', 'locked_out', 'logon_count')
    list_filter = ('locked_out', 'enabled', 'principal_source', 'department')
    search_fields = ('user__sid', 'user__email', 'department', 'job_title', 'description')
    readonly_fields = ('last_login_ip', 'logon_count', 'last_logon', 'last_password_change')
    fieldsets = (
        (None, {'fields': ('user', 'image')}),
        ('Personal Info', {'fields': ('description', 'department', 'job_title', 'time_zone', 'preferences')}),
        ('Security Info', {'fields': ('locked_out', 'lockout_time', 'enabled', 'account_expires', 'password_expires',
                                      'password_last_set', 'last_logon', 'user_may_change_password', 'password_required',
                                      'password_changeable_date', 'last_login_ip', 'last_password_change', 'logon_count')}),
        ('Windows Info', {'fields': ('principal_source', 'object_class', 'local_groups')}),
    )

    # Custom display method for user SID
    def user_sid(self, obj):
        return obj.user.sid
    user_sid.short_description = "User SID"
    user_sid.admin_order_field = 'user__sid'



