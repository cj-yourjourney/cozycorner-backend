from rest_framework import serializers


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)



from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import re


class UserSignupSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    
    Validates username, email, and password according to business rules
    and Django's built-in password validation.
    """
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'},
        help_text="Password must be at least 8 characters long"
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
        help_text="Confirm your password"
    )
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm')
        extra_kwargs = {
            'username': {
                'help_text': 'Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.',
            },
            'email': {
                'required': True,
                'help_text': 'Required. Enter a valid email address.',
            }
        }

    def validate_username(self, value):
        """
        Validate username according to business rules.
        """
        if not value:
            raise serializers.ValidationError("Username is required.")
            
        # Check for minimum length
        if len(value) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
            
        # Check for valid characters (alphanumeric, @, ., +, -, _)
        if not re.match(r'^[\w.@+-]+$', value):
            raise serializers.ValidationError(
                "Username may only contain letters, numbers, and @/./+/-/_ characters."
            )
            
        # Check for uniqueness
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
            
        return value

    def validate_email(self, value):
        """
        Validate email address.
        """
        if not value:
            raise serializers.ValidationError("Email address is required.")
            
        # Basic email format validation (additional to Django's EmailField validation)
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, value):
            raise serializers.ValidationError("Enter a valid email address.")
            
        # Check for uniqueness
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email address already exists.")
            
        return value.lower()  # Store email in lowercase

    def validate_password(self, value):
        """
        Validate password using Django's built-in validators.
        """
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, attrs):
        """
        Validate that password and password_confirm match.
        """
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')
        
        if password != password_confirm:
            raise serializers.ValidationError({
                'password_confirm': 'Password confirmation does not match.'
            })
            
        # Remove password_confirm from validated data as it's not needed for user creation
        attrs.pop('password_confirm', None)
        return attrs

    def create(self, validated_data):
        """
        Create and return a new User instance with hashed password.
        """
        username = validated_data['username']
        email = validated_data['email']
        password = validated_data['password']
        
        # Use create_user method to ensure password is properly hashed
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        
        return user


class UserResponseSerializer(serializers.ModelSerializer):
    """
    Serializer for user data in API responses (excludes sensitive information).
    """
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'date_joined')
        read_only_fields = ('id', 'date_joined')
