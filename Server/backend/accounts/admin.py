# accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import CustomUser, UserProfile, PasswordHistory

# class UserProfileInline(admin.StackedInline):
#     model = UserProfile
#     fields = (
#         'enabled', 'locked_out', 'client_id', 
#         'password_expires', 'last_logon', 'last_login_ip'
#     )
#     readonly_fields = ('last_logon', 'last_login_ip')
#     extra = 0



# class CustomUserAdmin(UserAdmin):
#     list_display = ('sid', 'email', 'is_active', 'last_login_display')
#     list_filter = ('is_active', 'is_staff', 'is_superuser')
#     search_fields = ('sid', 'email')
#     ordering = ('-created_at',)
#     inlines = [UserProfileInline]
    
#     fieldsets = (
#         (None, {'fields': ('sid', 'email', 'password')}),
#         ('Permissions', {
#             'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
#         }),
#         ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
#     )
#     readonly_fields = ('created_at', 'updated_at')
    
#     @admin.display(description='Last Login')
#     def last_login_display(self, obj):
#         if obj.last_login:
#             return obj.last_login.strftime('%Y-%m-%d %H:%M')
#         return "Never"

# class UserProfileAdmin(admin.ModelAdmin):
#     list_display = ('user', 'enabled', 'locked_out', 'client_id_truncated', 'logon_count')
#     list_filter = ('enabled', 'locked_out')
#     search_fields = ('user__sid', 'user__email', 'client_id')
#     readonly_fields = ('last_logon', 'last_login_ip', 'logon_count')
    
#     @admin.display(description='Client ID')
#     def client_id_truncated(self, obj):
#         if obj.client_id:
#             return f"{obj.client_id[:15]}..." if len(obj.client_id) > 15 else obj.client_id
#         return "-"


# class PasswordHistoryAdmin(admin.ModelAdmin):
#     list_display = ('user', 'changed_at')
#     search_fields = ('user__sid', 'user__email')
#     readonly_fields = ('user', 'hashed_password', 'changed_at')
    
#     def has_add_permission(self, request):
#         return False

# admin.site.register(CustomUser, CustomUserAdmin)
# admin.site.register(UserProfile, UserProfileAdmin)

# admin.site.register(PasswordHistory, PasswordHistoryAdmin)


