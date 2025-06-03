from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import LoginSerializer
from django.contrib.auth.models import User


class LoginView(APIView):
    permission_classes = []  # No auth required

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
            )

        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]
        user = authenticate(username=username, password=password)

        if user is None:
            return Response(
                {"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            return Response(
                {"detail": "User account is inactive."},
                status=status.HTTP_403_FORBIDDEN,
            )

        return Response(
            {
                "message": "Login successful.",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
            },
            status=status.HTTP_200_OK,
        )


from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.db import IntegrityError
import logging

from .serializers import UserSignupSerializer, UserResponseSerializer

# Configure logging
logger = logging.getLogger(__name__)


@api_view(["POST"])
@permission_classes([AllowAny])
def user_signup_view(request):
    """
    Handle user registration requests.

    This endpoint allows unauthenticated users to create new accounts.

    Args:
        request: HTTP request containing user registration data

    Returns:
        Response: JSON response with user data or error messages

    Example:
        POST /api/users/signup
        {
            "username": "johndoe",
            "email": "john@example.com",
            "password": "securepassword123",
            "password_confirm": "securepassword123"
        }

    Success Response (201):
        {
            "success": true,
            "message": "User created successfully",
            "user": {
                "id": 1,
                "username": "johndoe",
                "email": "john@example.com",
                "date_joined": "2024-01-15T10:30:00Z"
            }
        }

    Error Response (400):
        {
            "success": false,
            "message": "Validation failed",
            "errors": {
                "username": ["A user with this username already exists."],
                "email": ["Enter a valid email address."]
            }
        }
    """
    if request.method == "POST":
        try:
            # Initialize serializer with request data
            serializer = UserSignupSerializer(data=request.data)

            # Validate input data
            if serializer.is_valid():
                # Create new user
                user = serializer.save()

                # Prepare response data
                user_serializer = UserResponseSerializer(user)

                # Log successful registration
                logger.info(f"New user registered: {user.username} ({user.email})")

                return Response(
                    {
                        "success": True,
                        "message": "User created successfully",
                        "user": user_serializer.data,
                    },
                    status=status.HTTP_201_CREATED,
                )

            else:
                # Return validation errors
                logger.warning(
                    f"User registration failed - validation errors: {serializer.errors}"
                )

                return Response(
                    {
                        "success": False,
                        "message": "Validation failed",
                        "errors": serializer.errors,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except IntegrityError as e:
            # Handle database integrity errors (unlikely due to serializer validation)
            logger.error(f"Database integrity error during user registration: {str(e)}")

            return Response(
                {
                    "success": False,
                    "message": "A user with this information already exists",
                    "errors": {
                        "non_field_errors": [
                            "User creation failed due to duplicate data"
                        ]
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            # Handle unexpected errors
            logger.error(f"Unexpected error during user registration: {str(e)}")

            return Response(
                {
                    "success": False,
                    "message": "An unexpected error occurred",
                    "errors": {"non_field_errors": ["Internal server error"]},
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    # Method not allowed
    return Response(
        {
            "success": False,
            "message": "Method not allowed",
            "errors": {"method": ["Only POST requests are allowed"]},
        },
        status=status.HTTP_405_METHOD_NOT_ALLOWED,
    )
