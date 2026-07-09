from functools import wraps
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import user_passes_test, login_required as django_login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.urls import reverse


def login_required(view_func=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    return django_login_required(
        view_func,
        redirect_field_name=redirect_field_name,
        login_url=login_url,
    )


def admin_required(view_func=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    actual_decorator = user_passes_test(
        lambda u: u.is_authenticated and u.groups.filter(name='Admin').exists(),
        login_url=login_url,
        redirect_field_name=redirect_field_name,
    )
    if view_func:
        return actual_decorator(view_func)
    return actual_decorator


def worker_required(view_func=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    actual_decorator = user_passes_test(
        lambda u: u.is_authenticated and u.groups.filter(name='Worker').exists(),
        login_url=login_url,
        redirect_field_name=redirect_field_name,
    )
    if view_func:
        return actual_decorator(view_func)
    return actual_decorator


def admin_or_worker_required(view_func=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    actual_decorator = user_passes_test(
        lambda u: u.is_authenticated and (
            u.groups.filter(name='Admin').exists() or u.groups.filter(name='Worker').exists()
        ),
        login_url=login_url,
        redirect_field_name=redirect_field_name,
    )
    if view_func:
        return actual_decorator(view_func)
    return actual_decorator


class LoginRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('{}?next={}'.format(reverse('login'), request.path))
        return super().dispatch(request, *args, **kwargs)


class AdminRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('{}?next={}'.format(reverse('login'), request.path))
        if not request.user.groups.filter(name='Admin').exists():
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)


class WorkerRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('{}?next={}'.format(reverse('login'), request.path))
        if not request.user.groups.filter(name='Worker').exists():
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)


class AdminOrWorkerRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('{}?next={}'.format(reverse('login'), request.path))
        if not (request.user.groups.filter(name='Admin').exists() or
                request.user.groups.filter(name='Worker').exists()):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)
