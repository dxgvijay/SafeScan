from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import EmailHeaderScan, EmailHealthCheck, SuspiciousEmailReport


@admin.register(EmailHeaderScan)
class EmailHeaderScanAdmin(admin.ModelAdmin):
    list_display = ['user', 'sender_ip', 'spf_result', 'dkim_result', 'dmarc_result', 'threat_score', 'created_at']
    list_filter = ['spf_result', 'dkim_result', 'dmarc_result', 'threat_score', 'created_at']
    search_fields = ['user__email', 'user__username', 'sender_ip']
    readonly_fields = ['raw_headers', 'parsed_json', 'routing_hops', 'threat_score', 'created_at']
    ordering = ['-created_at']

    def has_add_permission(self, request):
        return False


@admin.register(EmailHealthCheck)
class EmailHealthCheckAdmin(admin.ModelAdmin):
    list_display = ['user', 'domain', 'health_score', 'created_at']
    list_filter = ['health_score', 'created_at']
    search_fields = ['domain', 'user__email']
    readonly_fields = [f.name for f in EmailHealthCheck._meta.fields]
    ordering = ['-created_at']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(SuspiciousEmailReport)
class SuspiciousEmailReportAdmin(admin.ModelAdmin):
    list_display = ['user', 'sender_email', 'risk_score', 'verdict', 'created_at']
    list_filter = ['verdict', 'risk_score', 'created_at']
    search_fields = ['sender_email', 'email_subject', 'user__email']
    readonly_fields = [f.name for f in SuspiciousEmailReport._meta.fields]
    ordering = ['-created_at']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
