import base64
from rest_framework.views import APIView
from common_utils.response_utils import ErrorResponse, SuccessResponse
from core_app.models import App_User, Authorization
from common_utils.jwt_auth_utils import create_jwt_token, decode_jwt_token, validate_jwt_token
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .serializers import LoginViewSerializer, RegisterViewSerializer
import logging

logger = logging.getLogger(__name__)

class RegisterUserView(APIView):
    """
    POST API endpoint for User Registration
    in this we get the email, mobile, password and user_name in the request 
    and in the response we send the success or failure message as per the logic.
    """
    def post(self, request):
        logger.info("RegisterUserView POST request initiated")
        try:
            serializer = RegisterViewSerializer(data=request.data)
            if not serializer.is_valid():
                return ErrorResponse(
                    code="TPE101",
                    status_="ERROR",
                    msg="Invalid input data.",
                    payload=serializer.errors
                )
            email = serializer.validated_data["email"]
            mobile = serializer.validated_data["mobile"]
            username = serializer.validated_data["username"]
            password = serializer.validated_data["password"]
            
            user = App_User.objects.filter(email=email, is_active = True)
            if user:
                return ErrorResponse(code="TPE102", status_="ERROR", msg=f"User already present : {str(e)}", payload={})

            user_created = App_User.objects.create(email=email, user_name=username, mobile=mobile, password=password)
            if user_created:
                return SuccessResponse(code="TPS100", status_="SUCCESS", msg ="User Created Successfully", payload = {"message" : "User Created Successfully, Now you can Login to the system"})

        except Exception as e:
            logger.exception(f"RegisterAPIView : Exception Occurred : {str(e)}")
            return ErrorResponse(code="TPE101", status_="ERROR", msg=f"An unexpected error occurred : {str(e)}", payload={})



def build_user_payload(user, token=None, extra=None):
    """Builds a consistent user payload for responses."""
    payload = {
        "email": user.email,
        "user_id": user.user_name,
        "mobile": user.mobile,
    }
    if token is not None:
        payload["token"] = token
    if extra:
        payload.update(extra)
    return payload


def is_password_valid(password, stored_password):
    """
    Validates password safely.
    """
    try:
        if password != stored_password:    
            return False
        return True
    
    except Exception:
        return False


class LoginAPIView(APIView):
    """
    POST API endpoint for user login.

    url : {domain}/trustee/v1/login
    Request body:
    {
      "username": "<username>",
      "password": "<password>",
      "continue_session": true | false | null (or omitted)
    }

    Behavior additions per requirement:
    - If an active session exists, we first validate the existing token.
      - If the token is VALID → proceed with the chosen flow:
          * continue_session is None → prompt to continue (return existing valid token).
          * continue_session is True → rotate token (deactivate old, create new).
          * continue_session is False → deactivate all active sessions (logout everywhere).
      - If the token is INVALID/EXPIRED → deactivate the active session(s) and create a NEW session
        with a NEW token (proceeds like a normal login), regardless of continue_session flag.
    """

    def post(self, request):
        logger.info("LoginAPIView POST request initiated")
        try:

            serializer = LoginViewSerializer(data=request.data)
            if not serializer.is_valid():
                return ErrorResponse(
                    code="TPE101",
                    status_="ERROR",
                    msg="Invalid input data.",
                    payload=serializer.errors
                )

            username = serializer.validated_data["username"]
            password = serializer.validated_data["password"]
            continue_session = serializer.validated_data.get("continue_session", None)  # None | True | False

            # 1) Find active user
            try:
                user = App_User.objects.get(email=username, is_active=True)
            except App_User.DoesNotExist:
                # Avoid user enumeration
                return ErrorResponse(code="TPE102", status_="ERROR", msg="Invalid username or password", payload={})

            # 2) Validate credentials BEFORE any session operations
            if not is_password_valid(password, user.password):
                return ErrorResponse(code="TPE103", status_="ERROR", msg="Invalid username or password", payload={})

            user_key = user.email
            
            # 3) Session logic starts here
            try:
                # Fetch existing active sessions
                active_session = Authorization.objects.filter(user=user_key, is_active=True).first()

                # Utility lambdas
                def _deactivate_all_active_sessions():
                    return (
                        Authorization.objects
                        .filter(user=user_key, is_active=True)
                        .update(is_active=False, token=None, modified_by=user.email)
                    )

                def _create_new_active_session():
                    new_token = create_jwt_token(user.email, user.user_name)
                    Authorization.objects.create(user=user_key, token=new_token, is_active=True, created_by=user.email)
                    return new_token

                # === Case: Active session exists → validate its token ===
                if active_session:
                    token_in_db = active_session.token

                    # A missing token is treated as invalid
                    if token_in_db:
                        is_valid_token = validate_jwt_token(token_in_db)
                    else:
                        is_valid_token = False

                    # If token invalid/expired → deactivate and create new session (normal flow)
                    if not is_valid_token:
                        deactivated_count = _deactivate_all_active_sessions()
                        new_token = _create_new_active_session()

                        payload = build_user_payload(user, token=new_token, extra={"previous_sessions_deactivated": deactivated_count})


                        return SuccessResponse(
                            code="TPS100",
                            status_="SUCCESS",
                            msg="Previous session invalid/expired. New session started.",
                            payload=payload
                        )

                    # Token is valid → honor continue_session flag
                    if continue_session is None:
                        # Prompt user to continue with current valid session
                        payload = build_user_payload(
                            user,
                            token=active_session.token,
                            extra={"message": "Active session found. Do you still want to continue this session?"}
                        )

                        return SuccessResponse(
                            code="TPS100",
                            status_="SUCCESS",
                            msg="Active session found. Do you still want to continue this session ?",
                            payload=payload
                        )

                    if continue_session is True:
                        # token: deactivate old, create new
                        active_session.is_active = False
                        active_session.token = None
                        active_session.modified_by = user.email
                        active_session.save(update_fields=["is_active", "token", "modify_by", "modified"])

                        new_token = _create_new_active_session()
                        payload = build_user_payload(user, token=new_token)
                        logger.info("LoginAPIView: Rotated valid session and issued new token.")


                        return SuccessResponse(
                            code="TPS100",
                            status_="SUCCESS",
                            msg="Previous session closed. New session started.",
                            payload=payload
                        )

                # === Case: No active session exists → normal login, create new session ===
                _new_token = _create_new_active_session()
                payload = build_user_payload(user, token=_new_token)
                logger.info("LoginAPIView: No active session; created new session and token.")

                return SuccessResponse(
                    code="TPS100",
                    status_="SUCCESS",
                    msg="Login Successful",
                    payload=payload
                )

            except Exception:
                # Log full details; return a generic error message to client
                logger.exception("LoginAPIView: Unhandled exception.")
                return ErrorResponse(
                    code="TPE104",
                    status_="ERROR",
                    msg="An unexpected error occurred. Please try again later.",
                    payload={}
                )

        except Exception:
            # Log full details; return a generic error message to client
            logger.exception("LoginAPIView: Unhandled exception.")
            return ErrorResponse(
                code="TPE105",
                status_="ERROR",
                msg="An unexpected error occurred. Please try again later.",
                payload={}
            )


class LogoutAPIView(APIView):
    """
    GET API endpoint for user logout.
    url : {domain}/trustee/v1/logout
    Header: Authorization: Bearer <token>
    """
    def get(self, request):
        logger.info("LogoutAPIView GET request initiated")
        try:
            # Extract token from Authorization header
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return ErrorResponse(code="TPE101", status_="ERROR", msg="Missing or invalid Authorization header.", payload={})
            token = auth_header.split(' ')[1]

            payload = decode_jwt_token(token)
            if not payload or 'email' not in payload:
                return ErrorResponse(code="TPE102", status_="ERROR", msg="Invalid or expired token.", payload={})

            user_key = payload['email']
            try:
                user = App_User.objects.get(email=user_key, is_active=True)
            except App_User.DoesNotExist:
                return ErrorResponse(code="TPE103", status_="ERROR", msg="User does not exist.", payload={})
            
            # Find active session for this user
            try:
                session = Authorization.objects.filter(user=user_key, is_active=True).first()
                if session:
                    session.is_active = False
                    session.token = None
                    session.modified_by = user_key
                    session.save(update_fields=['is_active', 'token', 'modified_by', 'modified_at'])
                    logger.info("LogoutAPIView: Session deactivated for user")
                else:
                    logger.info("LogoutAPIView: No active session found for user")

            except Exception as db_exc:
                logger.error(f"LogoutAPIView: DB Exception occured: {str(db_exc)}")
                return ErrorResponse(code="TPE104", status_="ERROR", msg="Session management failed.", payload={})

            response_data = {
                "logout_flag": True,
                "message": "Logout Successful"
            }
            logger.info("LogoutAPIView GET request completed successfully")
            return SuccessResponse(code="TPS100", status_="SUCCESS", msg="Logout successful", payload=response_data)
        
        except Exception as e:
            logger.exception(f"LogoutAPIView : Exception Occurred : {str(e)}")
            return ErrorResponse(code="TPE101", status_="ERROR", msg=f"An unexpected error occurred : {str(e)}", payload={})


def decrypt_password(encrypted_text):
    AES_IV = b'coreinvestorport'
    AES_KEY = b"anyrandomkey1234"  # 16,24,32 bytes
    try:
        encrypted_bytes = base64.b64decode(encrypted_text)
        cipher = Cipher(algorithms.AES(AES_KEY),modes.CBC(AES_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
        # Remove PKCS7 padding
        pad_len = decrypted_padded[-1]
        if pad_len > 16:
            raise ValueError("Invalid padding length")
        decrypted = decrypted_padded[:-pad_len]
        return decrypted.decode('utf-8')
    except Exception as e:
        return None

