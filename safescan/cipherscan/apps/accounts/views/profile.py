from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import TemplateView
from apps.accounts.decorators import LoginRequiredMixin
from apps.accounts.forms.profile import ProfileUpdateForm, PasswordChangeForm


class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = "pages/profile.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["page_title"] = "Profile"
        if 'profile_form' not in kwargs:
            context['profile_form'] = ProfileUpdateForm(instance=self.request.user, request=self.request)
        if 'password_form' not in kwargs:
            context['password_form'] = PasswordChangeForm(user=self.request.user)
        return context

    def post(self, request, *args, **kwargs):
        if 'update_profile' in request.POST:
            form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user, request=request)
            if form.is_valid():
                form.save()
                messages.success(request, 'Profile updated successfully.')
                return redirect('profile')
            return self.render_to_response(self.get_context_data(profile_form=form))

        elif 'change_password' in request.POST:
            form = PasswordChangeForm(request.POST, user=request.user)
            if form.is_valid():
                request.user.set_password(form.cleaned_data['new_password1'])
                request.user.save()
                update_session_auth_hash(request, request.user)
                messages.success(request, 'Password changed successfully.')
                return redirect('profile')
            return self.render_to_response(self.get_context_data(password_form=form))

        return redirect('profile')
