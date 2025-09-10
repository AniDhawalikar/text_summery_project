import jwt
from django.conf import settings
from datetime import datetime, timedelta, timezone


def create_jwt_token(email, username):
    payload = {
        'email': email,
        'username':username,
        'exp': datetime.now() + timedelta(minutes=30),
        'iat': datetime.now()
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def validate_jwt_token(token):
    """
    Validate JWT by manually checking expiration time.
    Returns True if token is valid (not expired), else False.
    """
    try:
        # Decode without verifying expiration automatically
        payload = decode_jwt_token(token)
        
        exp_timestamp = payload.get('exp')
        if not exp_timestamp:
            return False  # No expiry claim means invalid
        # Convert exp to datetime and compare with current UTC time
        exp_time = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        return datetime.now(timezone.utc) < exp_time

    except jwt.InvalidTokenError:
        return False
    except Exception:
        return False

