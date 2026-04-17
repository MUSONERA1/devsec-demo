from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import (
    UserCreationForm,
    PasswordChangeForm as DjangoPasswordChangeForm,
    PasswordResetForm as DjangoPasswordResetForm,
    SetPasswordForm as DjangoSetPasswordForm,
)
from .models import UserProfile
from .file_upload_security import (
    validate_avatar,
    log_file_upload,
    MAX_AVATAR_SIZE,
)


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]


class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password'
        })
    )


class PasswordChangeForm(DjangoPasswordChangeForm):
    """Custom password change form with improved styling."""
    
    def __init__(self, user, *args, **kwargs):
        super().__init__(user, *args, **kwargs)
        # Add CSS classes to all fields
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})


class UserProfileForm(forms.ModelForm):
    """Form for editing user profile information."""
    
    first_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'First Name'
        })
    )
    last_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Last Name'
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email Address'
        })
    )
    
    class Meta:
        model = UserProfile
        fields = ['first_name', 'last_name', 'email', 'bio', 'phone_number', 'profile_picture']
        widgets = {
            'bio': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Tell us about yourself (max 500 characters)',
                'maxlength': '500'
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Phone Number (optional)',
                'type': 'tel'
            }),
            'profile_picture': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': 'image/jpeg,image/png,image/gif,image/webp',
                'id': 'profile-picture-input'
            }),
        }
        labels = {
            'bio': 'About You',
            'phone_number': 'Phone Number',
            'profile_picture': 'Profile Picture',
            'first_name': 'First Name',
            'last_name': 'Last Name',
            'email': 'Email Address'
        }
        help_texts = {
            'profile_picture': f'JPG, PNG, GIF, or WebP (max {MAX_AVATAR_SIZE // (1024*1024)}MB)'
        }
    
    def __init__(self, *args, request=None, **kwargs):
        # Extract user from kwargs to avoid breaking Django's form data handling
        # This is critical for CSRF protection to work correctly
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        # Store request for audit logging
        self.request = request
        # Pre-fill user's basic info
        if user:
            self.fields['first_name'].initial = user.first_name
            self.fields['last_name'].initial = user.last_name
            self.fields['email'].initial = user.email
    
    def clean_profile_picture(self):
        """Validate profile picture on form submission."""
        profile_picture = self.cleaned_data.get('profile_picture')
        if profile_picture:
            try:
                validate_avatar(profile_picture)
            except forms.ValidationError as e:
                # Log failed upload attempt
                if self.request and self.request.user.is_authenticated:
                    log_file_upload(
                        self.request,
                        self.request.user.id,
                        profile_picture.name,
                        profile_picture.size,
                        'unknown',
                        'failed',
                        str(e)
                    )
                raise
        return profile_picture
    
    def save(self, commit=True, user=None, request=None):
        """Save both User and UserProfile information with upload logging."""
        profile = super().save(commit=False)
        
        # Ensure user relationship is set (required for OneToOneField)
        if user:
            profile.user = user
        
        # Log successful upload if profile_picture was updated
        if profile.profile_picture and request and request.user.is_authenticated:
            # Detect MIME type
            from .file_upload_security import check_magic_bytes, ALLOWED_AVATAR_MIMES
            mime_type = check_magic_bytes(profile.profile_picture, ALLOWED_AVATAR_MIMES)
            
            log_file_upload(
                request,
                request.user.id,
                profile.profile_picture.name,
                profile.profile_picture.size,
                mime_type or 'unknown',
                'success'
            )
        
        # Update User model fields
        if user:
            user.first_name = self.cleaned_data.get('first_name', '')
            user.last_name = self.cleaned_data.get('last_name', '')
            user.email = self.cleaned_data.get('email', '')
            if commit:
                user.save()
        
        # Save UserProfile
        if commit:
            profile.save()
        
        return profile


class PasswordResetForm(DjangoPasswordResetForm):
    """
    Custom password reset form with improved styling.
    
    Uses Django's built-in PasswordResetForm which:
    - Sends secure token-based password reset links via email
    - Uses Django's token generation (PBKDF2WithSHA256)
    - Validates that user exists before sending email (safe against enumeration)
    - Does not leak whether email is registered (generic message)
    
    Security Notes:
    - Django's tokens expire after TOKEN_PASSWORD_RESET_TIMEOUT (default 3 days)
    - Tokens are one-time use (consumed after successful password reset)
    - Email is sent only if account exists (prevents user enumeration)
    - Generic confirmation message shown regardless of result
    """
    email = forms.EmailField(
        label="Email Address",
        max_length=254,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your registered email address',
            'autocomplete': 'email'
        })
    )


class SetPasswordForm(DjangoSetPasswordForm):
    """
    Custom set password form for password reset confirmation.
    
    Uses Django's built-in SetPasswordForm which:
    - Validates password strength (matching Django's PASSWORD_VALIDATORS)
    - Validates two password fields match
    - Provides clear validation error messages
    - Prevents password reuse (if configured)
    
    Security Notes:
    - Passwords must meet Django's validation rules:
      * Minimum length (usually 8 characters)
      * Cannot be entirely numeric
      * Cannot be similar to username
      * Cannot be in common password list
    - Both password fields required for confirmation
    - Error messages help user fix issues
    """
    new_password1 = forms.CharField(
        label="New Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter a strong password',
            'autocomplete': 'new-password'
        }),
        strip=False
    )
    new_password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm your password',
            'autocomplete': 'new-password'
        }),
        strip=False
    )


# ==========================================
# PASSWORD RESET FORMS (Task #35)
# ==========================================
# Uses Django's built-in password reset utilities
# for secure token generation and management

class PasswordResetRequestForm(DjangoPasswordResetForm):
    """
    Form for requesting a password reset.
    
    Security features:
    - Uses Django's built-in PasswordResetForm
    - Prevents user enumeration through generic messaging
    - Securely validates email without leaking existence info
    - Includes CSRF protection
    """
    
    email = forms.EmailField(
        label="Email Address",
        max_length=254,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address',
            'autocomplete': 'email',
        })
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add custom styling
        self.fields['email'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Enter your registered email address',
        })


class SetPasswordForm(DjangoSetPasswordForm):
    """
    Form for setting a new password after reset confirmation.
    
    Security features:
    - Uses Django's built-in SetPasswordForm
    - Validates password strength using AUTH_PASSWORD_VALIDATORS
    - Prevents weak passwords
    - Includes CSRF protection
    - Requires password confirmation (matches validation)
    """
    
    new_password1 = forms.CharField(
        label="New Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new password',
            'autocomplete': 'new-password',
        }),
        help_text="Password must be at least 8 characters long."
    )
    new_password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm new password',
            'autocomplete': 'new-password',
        })
    )
    
    def __init__(self, user, *args, **kwargs):
        super().__init__(user, *args, **kwargs)
        # Enhanced password requirements help text
        self.fields['new_password1'].help_text = (
            "Your password must be at least 8 characters long and cannot be "
            "entirely numeric or a common password. It will be encrypted when saved."
        )