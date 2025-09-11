from django.db import models
from django.utils import timezone
from datetime import timedelta


class BaseField(models.Model):
    created_by = models.CharField(null=True, blank=True, max_length=255)
    modified_by = models.CharField(null=True, blank=True, max_length=255)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    modified_at = models.DateTimeField(auto_now=True ,null=True, blank=True)
    is_active = models.BooleanField(default=True)


class App_User(BaseField):
    email = models.EmailField(unique=True)
    user_name = models.CharField(max_length=255)
    mobile = models.CharField(max_length=15)
    password = models.CharField(max_length=255)
    
    def __str__(self):
        return self.email



def _default_expiry():
    """
    Default expiry is 'now + TTL'. This is preferred over auto_now_add=True,
    because expiry should be derived from creation, not equal to creation.
    """
    return timezone.now() + timedelta(minutes = 30)

class Authorization(BaseField):
    user = models.EmailField()
    token = models.CharField(max_length=550, null=True, blank=True)
    expiry_time = models.DateTimeField(default = _default_expiry)

    def __str__(self):
        return self.user

