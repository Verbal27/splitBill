from rest_framework import generics, viewsets, permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from .serializers import LoginSerializer, RegisterSerializer, UserUpdateSerializer
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth.models import User


class Register(generics.CreateAPIView):
    def get(self, request, *args, **kwargs):
        return Response({"message": "Post to create user"})
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


class Login(generics.GenericAPIView):
    serializer_class = LoginSerializer
    authentication_classes = [TokenAuthentication]

    def get(self, request, *args, **kwargs):
        return Response({"message": "Post to login user"})

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data,
                                         context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            "message": "You're in!",
            'token': token.key,
            'user_id': user.pk,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
        })


class UpdateUserView(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserUpdateSerializer

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)


class Logout(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        request.auth.delete()
        return Response(status=204)
