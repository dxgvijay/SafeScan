from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from apps.accounts.signals import assign_role


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form=form)
        assign_role(user, 'User')
        return user
