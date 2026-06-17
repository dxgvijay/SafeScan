from django import forms
from django.contrib.auth import password_validation, authenticate
from django.contrib.auth.forms import PasswordChangeForm as BasePasswordChangeForm
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import CustomUser


class RegisterForm(forms.ModelForm):
    email = forms.EmailField(
        label=_('Email'),
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autocomplete': 'email',
        }),
    )
    username = forms.CharField(
        label=_('Username'),
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Choose a username',
            'autocomplete': 'username',
        }),
    )
    password1 = forms.CharField(
        label=_('Password'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Create a password',
            'autocomplete': 'new-password',
        }),
    )
    password2 = forms.CharField(
        label=_('Confirm Password'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Repeat your password',
            'autocomplete': 'new-password',
        }),
    )
    terms_accepted = forms.BooleanField(
        label=_('I accept the Terms of Service and Privacy Policy'),
        required=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )

    class Meta:
        model = CustomUser
        fields = ['email', 'username']

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError(_('A user with this email already exists.'))
        return email

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        if CustomUser.objects.filter(username=username).exists():
            raise ValidationError(_('This username is already taken.'))
        if len(username) < 3:
            raise ValidationError(_('Username must be at least 3 characters long.'))
        return username

    def clean_password1(self):
        password1 = self.cleaned_data.get('password1', '')
        try:
            password_validation.validate_password(password1)
        except ValidationError as e:
            raise ValidationError(list(e.messages))
        return password1

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise ValidationError({'password2': _('Passwords do not match.')})
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        user.is_active = True
        if commit:
            user.save()
        return user


class LoginForm(forms.Form):
    email = forms.EmailField(
        label=_('Email'),
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autocomplete': 'email',
            'autofocus': True,
        }),
    )
    password = forms.CharField(
        label=_('Password'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password',
            'autocomplete': 'current-password',
        }),
    )
    remember_me = forms.BooleanField(
        label=_('Remember me'),
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email', '').strip().lower()
        password = cleaned_data.get('password', '')

        if email and password:
            try:
                user = CustomUser.objects.get(email=email)
                if not user.is_active:
                    raise ValidationError(
                        _('This account is inactive. Please contact support.')
                    )
            except CustomUser.DoesNotExist:
                raise ValidationError(
                    _('No account found with this email address.')
                )

            user = authenticate(request=self.request, email=email, password=password)
            if user is None:
                raise ValidationError(_('Invalid email or password.'))

            cleaned_data['user'] = user

        return cleaned_data


class ProfileUpdateForm(forms.ModelForm):
    email = forms.EmailField(
        label=_('Email'),
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'autocomplete': 'email',
        }),
    )
    username = forms.CharField(
        label=_('Username'),
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'autocomplete': 'username',
        }),
    )
    bio = forms.CharField(
        label=_('Bio'),
        max_length=500,
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Tell us about yourself...',
        }),
    )
    avatar = forms.ImageField(
        label=_('Avatar'),
        required=False,
        widget=forms.FileInput(attrs={'class': 'form-control'}),
    )

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'bio', 'avatar']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if CustomUser.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError(_('This email is already in use.'))
        return email

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        if CustomUser.objects.filter(username=username).exclude(pk=self.instance.pk).exists():
            raise ValidationError(_('This username is already taken.'))
        if len(username) < 3:
            raise ValidationError(_('Username must be at least 3 characters long.'))
        return username

    def clean_avatar(self):
        avatar = self.cleaned_data.get('avatar')
        if avatar:
            if avatar.size > 5 * 1024 * 1024:
                raise ValidationError(_('Image must be less than 5MB.'))
            allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
            if hasattr(avatar, 'content_type') and avatar.content_type not in allowed_types:
                raise ValidationError(_('Only JPEG, PNG, GIF, and WebP images are allowed.'))
        return avatar


class ChangePasswordForm(BasePasswordChangeForm):
    old_password = forms.CharField(
        label=_('Current Password'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your current password',
            'autocomplete': 'current-password',
        }),
    )
    new_password1 = forms.CharField(
        label=_('New Password'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your new password',
            'autocomplete': 'new-password',
        }),
    )
    new_password2 = forms.CharField(
        label=_('Confirm New Password'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Repeat your new password',
            'autocomplete': 'new-password',
        }),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.pop('autofocus', None)
