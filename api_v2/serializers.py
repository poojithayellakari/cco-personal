from rest_framework import serializers
from .models import CustomUser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = CustomUser
        fields = ['id', 'full_name', 'email', 'password']
        read_only_fields = ['id']

    def create(self, validated_data):
        return CustomUser.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        user = CustomUser.objects.filter(email=email).first()
        if user and user.check_password(password):
            if user.is_active:
                data = super().validate(attrs)
                refresh = self.get_token(user)
                data["refresh"] = str(refresh)
                data["access"] = str(refresh.access_token)
                data['email'] = user.email
                return data
            else:
                raise serializers.ValidationError('Account is Blocked')
        else:
            raise serializers.ValidationError('Incorrect email/password combination!')