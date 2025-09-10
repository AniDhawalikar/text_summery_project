from django.urls import path
from .views import LoginAPIView, LogoutAPIView, RegisterUserView


urlpatterns = [
        path('register', RegisterUserView.as_view(), name='user_register'),
        path('login', LoginAPIView.as_view(), name='user_login'),
        path('logout', LogoutAPIView.as_view(), name='user_logout'),
]