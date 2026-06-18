from django.contrib.auth.views import LoginView as AuthLoginView


class LoginView(AuthLoginView):
    template_name = "pages/login.html"
    redirect_authenticated_user = True

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["page_title"] = "Sign In"
        return context
