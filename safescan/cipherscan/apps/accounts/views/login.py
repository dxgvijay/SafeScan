from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.views import LoginView as AuthLoginView
from django.shortcuts import redirect
from django.urls import reverse
from apps.accounts.forms.login import LoginForm


class LoginView(AuthLoginView):
    template_name = "pages/login.html"
    form_class = LoginForm
    redirect_authenticated_user = True

    def get_success_url(self):
        user = self.request.user
        if user.groups.filter(name='Admin').exists():
            return reverse('admin_panel')
        elif user.groups.filter(name='Worker').exists():
            return reverse('worker_dashboard')
        return reverse('dashboard')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["page_title"] = "Sign In"
        return context

    def form_valid(self, form):
        auth_login(self.request, form.get_user())
        return redirect(self.get_success_url())
