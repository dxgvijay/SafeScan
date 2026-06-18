from django.contrib.auth.views import LogoutView as AuthLogoutView


class LogoutView(AuthLogoutView):
    next_page = "home"
