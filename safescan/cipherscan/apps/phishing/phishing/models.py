import json
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class EmailHeaderScan(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='email_scans',
        verbose_name=_('user'),
    )
    raw_headers = models.TextField(_('raw headers'))
    parsed_json = models.JSONField(_('parsed headers'), default=dict, blank=True)
    sender_ip = models.GenericIPAddressField(_('sender IP'), blank=True, null=True)
    spf_result = models.CharField(_('SPF result'), max_length=20, blank=True)
    dkim_result = models.CharField(_('DKIM result'), max_length=20, blank=True)
    dmarc_result = models.CharField(_('DMARC result'), max_length=20, blank=True)
    routing_hops = models.JSONField(_('routing hops'), default=list, blank=True)
    threat_score = models.PositiveSmallIntegerField(_('threat score'), default=0)
    created_at = models.DateTimeField(_('created at'), default=timezone.now)

    class Meta:
        verbose_name = _('email header scan')
        verbose_name_plural = _('email header scans')
        ordering = ['-created_at']

    def __str__(self):
        sender = self.parsed_json.get('From', 'Unknown')
        return f'Email scan - {sender[:60]}'

    def save(self, *args, **kwargs):
        if isinstance(self.parsed_json, str):
            try:
                self.parsed_json = json.loads(self.parsed_json)
            except (json.JSONDecodeError, TypeError):
                pass
        if isinstance(self.routing_hops, str):
            try:
                self.routing_hops = json.loads(self.routing_hops)
            except (json.JSONDecodeError, TypeError):
                pass
        super().save(*args, **kwargs)


class SuspiciousEmailReport(models.Model):
    VERDICT_CHOICES = [
        ('clean', _('Clean')),
        ('suspicious', _('Suspicious')),
        ('phishing', _('Phishing')),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='suspicious_email_reports',
        verbose_name=_('user'),
    )
    email_subject = models.CharField(_('subject'), max_length=500, blank=True)
    sender_email = models.EmailField(_('sender email'), max_length=254)
    sender_domain = models.CharField(_('sender domain'), max_length=255, blank=True)
    email_body = models.TextField(_('email body'), blank=True)
    attachments_info = models.JSONField(_('attachments info'), default=list, blank=True)
    links_found = models.JSONField(_('links found'), default=list, blank=True)
    phishing_indicators = models.JSONField(_('phishing indicators'), default=list, blank=True)
    risk_score = models.PositiveSmallIntegerField(_('risk score'), default=0)
    verdict = models.CharField(_('verdict'), max_length=20, choices=VERDICT_CHOICES, default='clean')
    created_at = models.DateTimeField(_('created at'), default=timezone.now)

    class Meta:
        verbose_name = _('suspicious email report')
        verbose_name_plural = _('suspicious email reports')
        ordering = ['-created_at']

    def __str__(self):
        return f'Suspicious email - {self.sender_email[:40]} - {self.get_verdict_display()}'

    def save(self, *args, **kwargs):
        if isinstance(self.attachments_info, str):
            try:
                self.attachments_info = json.loads(self.attachments_info)
            except (json.JSONDecodeError, TypeError):
                pass
        if isinstance(self.links_found, str):
            try:
                self.links_found = json.loads(self.links_found)
            except (json.JSONDecodeError, TypeError):
                pass
        if isinstance(self.phishing_indicators, str):
            try:
                self.phishing_indicators = json.loads(self.phishing_indicators)
            except (json.JSONDecodeError, TypeError):
                pass
        super().save(*args, **kwargs)


class EmailHealthCheck(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='email_health_checks',
        verbose_name=_('user'),
    )
    domain = models.CharField(_('domain'), max_length=255)
    mx_records = models.JSONField(_('MX records'), default=list, blank=True)
    spf_result = models.JSONField(_('SPF result'), default=dict, blank=True)
    dkim_results = models.JSONField(_('DKIM results'), default=list, blank=True)
    dmarc_result = models.JSONField(_('DMARC result'), default=dict, blank=True)
    blacklist_results = models.JSONField(_('blacklist results'), default=list, blank=True)
    ptr_result = models.JSONField(_('PTR result'), default=dict, blank=True)
    smtp_banner = models.TextField(_('SMTP banner'), blank=True)
    health_score = models.PositiveSmallIntegerField(_('health score'), default=0)
    score_breakdown = models.JSONField(_('score breakdown'), default=dict, blank=True)
    created_at = models.DateTimeField(_('created at'), default=timezone.now)

    class Meta:
        verbose_name = _('email health check')
        verbose_name_plural = _('email health checks')
        ordering = ['-created_at']

    def __str__(self):
        return f'Health check - {self.domain}'
