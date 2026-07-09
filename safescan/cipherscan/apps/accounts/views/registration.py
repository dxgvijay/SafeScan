from django.contrib.auth import login as auth_login
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView
from apps.accounts.models import CustomUser
from apps.accounts.forms.registration import SignupForm
from apps.accounts.signals import assign_role


class SignupView(CreateView):
    model = CustomUser
    form_class = SignupForm
    template_name = "pages/signup.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["page_title"] = "Create Account"
        return context

    def form_valid(self, form):
        user = form.save()
        assign_role(user, 'User')
        auth_login(self.request, user)
        return redirect(reverse_lazy('dashboard'))

    def get_success_url(self):
        return reverse_lazy('dashboard')
