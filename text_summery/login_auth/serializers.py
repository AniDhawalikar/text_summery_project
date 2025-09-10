from rest_framework import serializers

class LoginViewSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, allow_blank=False)
    password = serializers.CharField(required=True, allow_blank=False)
    continue_session = serializers.BooleanField(required=False, allow_null=True, default=None)


class RegisterViewSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, allow_blank=False)
    mobile = serializers.CharField(required=True, max_length=15, allow_blank=False)
    username = serializers.CharField(required=True, allow_blank=False)
    password = serializers.CharField(required=True, allow_blank=False)