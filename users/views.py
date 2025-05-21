# views.py
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserSignupSerializer


class UserSignupView(APIView):
    """
    API view for user signup.
    """

    def post(self, request, *args, **kwargs):
        serializer = UserSignupSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            # Return success response with user data (excluding password)
            response_data = {
                "status": "success",
                "message": "User registered successfully",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
            }

            return Response(response_data, status=status.HTTP_201_CREATED)

        # Return validation errors
        return Response(
            {
                "status": "error",
                "message": "Validation error",
                "errors": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
