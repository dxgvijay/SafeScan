from django.contrib.auth.views import LogoutView as AuthLogoutView
from django.contrib.auth import logout as auth_logout
from django.shortcuts import redirect
from django.urls import reverse


class LogoutView(AuthLogoutView):
    next_page = "home"

    def post(self, request, *args, **kwargs):
        auth_logout(request)
        return redirect(reverse('home'))

    def get(self, request, *args, **kwargs):
        auth_logout(request)
        return redirect(reverse('home'))
