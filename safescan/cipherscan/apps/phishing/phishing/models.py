import json
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class EmailHeaderScan(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='email_header_scans',
        verbose_name=_('user'),
        null=True,
        blank=True,
    )
    raw_header = models.TextField(_('raw header'))
    scanned_at = models.DateTimeField(_('scanned at'), auto_now_add=True)
    status = models.CharField(_('status'), max_length=50, default='complete')
    from_email = models.CharField(_('from email'), max_length=255, null=True, blank=True)
    sender_ip = models.CharField(_('sender IP'), max_length=100, null=True, blank=True)
    spf_result = models.CharField(_('SPF result'), max_length=50, null=True, blank=True)
    dkim_result = models.CharField(_('DKIM result'), max_length=50, null=True, blank=True)
    dmarc_result = models.CharField(_('DMARC result'), max_length=50, null=True, blank=True)
    spoofing_detected = models.BooleanField(_('spoofing detected'), default=False)
    threat_score = models.IntegerField(_('threat score'), default=0)
    is_malicious = models.BooleanField(_('is malicious'), default=False)
    hops = models.JSONField(_('hops'), null=True, blank=True)
    analysis_result = models.JSONField(_('analysis result'), null=True, blank=True)

    class Meta:
        verbose_name = _('email header scan')
        verbose_name_plural = _('email header scans')
        ordering = ['-scanned_at']

    def __str__(self):
        return f'Email scan - {self.from_email or "Unknown"}'


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


class DomainHealthScan(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='domain_health_scans',
        verbose_name=_('user'),
        null=True,
        blank=True,
    )
    domain = models.CharField(_('domain'), max_length=255)
    scanned_at = models.DateTimeField(_('scanned at'), auto_now_add=True)
    status = models.CharField(_('status'), max_length=50, default='complete')
    mx_records = models.JSONField(_('MX records'), null=True, blank=True)
    spf_record = models.TextField(_('SPF record'), null=True, blank=True)
    dkim_found = models.BooleanField(_('DKIM found'), default=False)
    dmarc_record = models.TextField(_('DMARC record'), null=True, blank=True)
    blacklist_hits = models.IntegerField(_('blacklist hits'), default=0)
    blacklists_checked = models.IntegerField(_('blacklists checked'), default=0)
    health_score = models.IntegerField(_('health score'), default=0)
    health_grade = models.CharField(_('health grade'), max_length=2, null=True, blank=True)
    issues = models.JSONField(_('issues'), null=True, blank=True)

    class Meta:
        verbose_name = _('domain health scan')
        verbose_name_plural = _('domain health scans')
        ordering = ['-scanned_at']

    def __str__(self):
        return f'Domain health - {self.domain}'


class EmailContentScan(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='email_content_scans',
        verbose_name=_('user'),
        null=True,
        blank=True,
    )
    email_body = models.TextField(_('email body'))
    scanned_at = models.DateTimeField(_('scanned at'), auto_now_add=True)
    status = models.CharField(_('status'), max_length=50, default='complete')
    phishing_score = models.IntegerField(_('phishing score'), default=0)
    verdict = models.CharField(_('verdict'), max_length=100, null=True, blank=True)
    is_phishing = models.BooleanField(_('is phishing'), default=False)
    indicators = models.JSONField(_('indicators'), null=True, blank=True)
    urls_found = models.JSONField(_('URLs found'), null=True, blank=True)
    keywords_found = models.JSONField(_('keywords found'), null=True, blank=True)

    class Meta:
        verbose_name = _('email content scan')
        verbose_name_plural = _('email content scans')
        ordering = ['-scanned_at']

    def __str__(self):
        return f'Content scan - {self.phishing_score} ({self.verdict or "Pending"})'
