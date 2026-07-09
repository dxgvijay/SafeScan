from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.db.models import Count, Q
from django_ratelimit.decorators import ratelimit

from .models import CustomUser, ScanHistory, APIKey
from .forms import (
    RegisterForm,
    LoginForm,
    ProfileUpdateForm,
    ChangePasswordForm,
)


def _send_verification_email(user, request):
    token = user.email_verification_token
    verify_url = request.build_absolute_uri(
        reverse('accounts:verify_email', kwargs={'token': token})
    )
    subject = _('Verify your email address - CipherScan')
    html_message = render_to_string('accounts/emails/verify_email.html', {
        'user': user,
        'verify_url': verify_url,
    })
    plain_message = strip_tags(html_message)
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
        fail_silently=False,
    )


@ratelimit(key='ip', rate='5/h', method='POST', block=True)
def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')

    form = RegisterForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        _send_verification_email(user, request)
        messages.success(
            request,
            _('Account created successfully! Please check your email to verify your account.'),
        )
        login(request, user)
        return redirect('dashboard:home')

    return render(request, 'accounts/register.html', {'form': form})


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')

    form = LoginForm(request.POST or None, request=request)
    if request.method == 'POST' and form.is_valid():
        user = form.cleaned_data['user']
        remember_me = form.cleaned_data.get('remember_me', True)

        if not user.is_verified:
            messages.warning(
                request,
                _('Please verify your email address before logging in. Check your inbox.'),
            )
            _send_verification_email(user, request)
            return render(request, 'accounts/login.html', {'form': form})

        login(request, user)

        if not remember_me:
            request.session.set_expiry(0)

        if user.two_factor_enabled:
            messages.info(request, _('Please complete your two-factor authentication.'))
            return redirect('two_factor:setup')

        messages.success(request, _(f'Welcome back, {user.username}!'))
        next_url = request.GET.get('next')
        if next_url:
            return redirect(next_url)
        return redirect('dashboard:home')

    return render(request, 'accounts/login.html', {'form': form})


def logout_view(request):
    logout(request)
    messages.info(request, _('You have been logged out successfully.'))
    return redirect('accounts:login')


@login_required
def dashboard_view(request):
    user = request.user

    today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    total_scans = ScanHistory.objects.filter(user=user).count()
    today_scans = ScanHistory.objects.filter(user=user, created_at__gte=today_start).count()
    malicious_finds = ScanHistory.objects.filter(
        user=user, verdict='MALICIOUS'
    ).count()
    recent_scans = ScanHistory.objects.filter(user=user)[:10]

    scan_counts = (
        ScanHistory.objects.filter(user=user)
        .values('scan_type')
        .annotate(count=Count('id'))
        .order_by('scan_type')
    )

    api_keys = APIKey.objects.filter(user=user, is_active=True)

    context = {
        'user': user,
        'total_scans': total_scans,
        'today_scans': today_scans,
        'malicious_finds': malicious_finds,
        'recent_scans': recent_scans,
        'scan_counts': scan_counts,
        'api_keys': api_keys,
        'can_scan': user.can_scan(),
        'scans_remaining': max(0, 10 - user.scan_count) if user.plan == 'free' else float('inf'),
    }
    return render(request, 'accounts/dashboard.html', context)


@login_required
def profile_view(request):
    user = request.user
    form = ProfileUpdateForm(
        request.POST or None,
        request.FILES or None,
        instance=user,
    )

    if request.method == 'POST' and form.is_valid():
        form.save()
        messages.success(request, _('Your profile has been updated successfully.'))
        return redirect('accounts:profile')

    context = {
        'form': form,
        'user': user,
    }
    return render(request, 'accounts/profile.html', context)


@login_required
def change_password_view(request):
    form = ChangePasswordForm(request.user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        form.save()
        update_session_auth_hash(request, form.user)
        messages.success(request, _('Your password has been changed successfully.'))
        return redirect('accounts:profile')

    context = {'form': form}
    return render(request, 'accounts/change_password.html', context)


def verify_email_view(request, token):
    user = get_object_or_404(CustomUser, email_verification_token=token)

    if user.is_verified:
        messages.info(request, _('Your email is already verified.'))
        return redirect('accounts:login')

    if user.email_verification_token != token:
        messages.error(request, _('Invalid or expired verification link.'))
        return redirect('accounts:login')

    user.is_verified = True
    user.email_verification_token = None
    user.save(update_fields=['is_verified', 'email_verification_token'])

    messages.success(request, _('Your email has been verified successfully! You can now log in.'))
    return redirect('accounts:login')


@login_required
def resend_verification_view(request):
    user = request.user
    if user.is_verified:
        messages.info(request, _('Your email is already verified.'))
        return redirect('accounts:profile')

    _send_verification_email(user, request)
    messages.success(request, _('A new verification email has been sent to your inbox.'))
    return redirect('accounts:profile')


@login_required
def enable_2fa_view(request):
    user = request.user
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'enable':
            user.two_factor_enabled = True
            user.save(update_fields=['two_factor_enabled'])
            messages.success(request, _('Two-factor authentication has been enabled.'))
            return redirect('two_factor:setup')
        elif action == 'disable':
            user.two_factor_enabled = False
            user.save(update_fields=['two_factor_enabled'])
            messages.success(request, _('Two-factor authentication has been disabled.'))
            return redirect('accounts:profile')

    context = {'two_factor_enabled': user.two_factor_enabled}
    return render(request, 'accounts/two_factor.html', context)
