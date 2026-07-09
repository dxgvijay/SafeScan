from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .models import CustomUser, ScanHistory, APIKey


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    list_display = [
        'email', 'username', 'plan', 'scan_count', 'is_verified',
        'two_factor_enabled', 'is_active', 'joined_date',
    ]
    list_filter = [
        'plan', 'is_verified', 'two_factor_enabled', 'is_active',
        'is_staff', 'joined_date',
    ]
    search_fields = ['email', 'username']
    ordering = ['-date_joined']
    readonly_fields = ['joined_date', 'scan_count', 'email_verification_token']

    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        (_('Personal Info'), {'fields': ('avatar', 'bio')}),
        (_('Account Details'), {
            'fields': ('plan', 'scan_count', 'is_verified', 'two_factor_enabled'),
        }),
        (_('Permissions'), {
            'fields': (
                'is_active', 'is_staff', 'is_superuser',
                'groups', 'user_permissions',
            ),
        }),
        (_('Important dates'), {
            'fields': ('last_login', 'date_joined', 'joined_date'),
        }),
        (_('Verification'), {
            'fields': ('email_verification_token',),
            'classes': ('collapse',),
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2'),
        }),
    )


@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ['user', 'scan_type', 'target_preview', 'verdict', 'created_at']
    list_filter = ['scan_type', 'verdict', 'created_at']
    search_fields = ['user__email', 'user__username', 'target']
    ordering = ['-created_at']

    def target_preview(self, obj):
        return obj.target[:60] + '...' if len(obj.target) > 60 else obj.target
    target_preview.short_description = _('target')


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'key_preview', 'is_active', 'created_at', 'last_used_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'user__email', 'key']
    readonly_fields = ['key', 'created_at', 'last_used_at']
    ordering = ['-created_at']

    def key_preview(self, obj):
        return f'{obj.key[:16]}...'
    key_preview.short_description = _('API key')
