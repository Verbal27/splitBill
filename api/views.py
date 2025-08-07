from rest_framework import generics
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from .serializers import UserSerializer, LoginSerializer
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication


class Register(generics.CreateAPIView):
    def get(self, request, *args, **kwargs):
        return Response({"message": "Post to create user"})
    serializer_class = UserSerializer
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
            'token': token.key,
            'user_id': user.pk,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'password': user.password
        })


class Logout(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        request.auth.delete()
        return Response(status=204)
