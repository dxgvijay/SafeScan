import uuid
import hashlib
import secrets
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.conf import settings


class CustomUser(AbstractUser):
    PLAN_CHOICES = [
        ('free', 'Free'),
        ('pro', 'Pro'),
    ]

    email = models.EmailField(_('email address'), unique=True)
    username = models.CharField(_('username'), max_length=150, unique=True)
    avatar = models.ImageField(_('avatar'), upload_to='avatars/', blank=True, null=True)
    bio = models.TextField(_('bio'), max_length=500, blank=True)
    plan = models.CharField(_('plan'), max_length=10, choices=PLAN_CHOICES, default='free')
    scan_count = models.PositiveIntegerField(_('scan count'), default=0)
    joined_date = models.DateTimeField(_('joined date'), default=timezone.now)
    is_verified = models.BooleanField(_('verified'), default=False)
    two_factor_enabled = models.BooleanField(_('two-factor enabled'), default=False)
    email_verification_token = models.CharField(_('email verification token'), max_length=64, blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        ordering = ['-date_joined']

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        if not self.email_verification_token:
            self.email_verification_token = hashlib.sha256(
                secrets.token_bytes(32)
            ).hexdigest()
        super().save(*args, **kwargs)

    def can_scan(self):
        if self.plan == 'pro':
            return True
        return self.scan_count < 10

    def increment_scan_count(self):
        self.scan_count = models.F('scan_count') + 1
        self.save(update_fields=['scan_count'])


class ScanHistory(models.Model):
    SCAN_TYPES = [
        ('url', 'URL Scan'),
        ('file', 'File Scan'),
        ('phishing', 'Phishing Scan'),
    ]

    THREAT_LEVELS = [
        ('safe', 'Safe'),
        ('suspicious', 'Suspicious'),
        ('malicious', 'Malicious'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scan_history',
        verbose_name=_('user'),
    )
    scan_type = models.CharField(_('scan type'), max_length=20, choices=SCAN_TYPES)
    target = models.CharField(_('target'), max_length=2048)
    result_json = models.JSONField(_('result'), default=dict, blank=True)
    threat_level = models.CharField(
        _('threat level'), max_length=20, choices=THREAT_LEVELS, default='safe'
    )
    created_at = models.DateTimeField(_('created at'), default=timezone.now)

    class Meta:
        verbose_name = _('scan history')
        verbose_name_plural = _('scan histories')
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.get_scan_type_display()} - {self.target[:50]}'


class APIKey(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='api_keys',
        verbose_name=_('user'),
    )
    key = models.CharField(_('key'), max_length=64, unique=True, editable=False)
    name = models.CharField(_('name'), max_length=100)
    is_active = models.BooleanField(_('active'), default=True)
    created_at = models.DateTimeField(_('created at'), default=timezone.now)
    last_used_at = models.DateTimeField(_('last used'), blank=True, null=True)

    class Meta:
        verbose_name = _('API key')
        verbose_name_plural = _('API keys')
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.key[:8]}...)'

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        super().save(*args, **kwargs)

    def regenerate(self):
        self.key = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        self.save(update_fields=['key'])
