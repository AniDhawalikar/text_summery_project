import logging
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework import status as rest_status
 
logger = logging.getLogger(__name__)
 
 
class SuccessResponse(Response):
 
    def __init__(self, msg, code=None, status_="SUCCESS", status=rest_status.HTTP_200_OK,
                 template_name=None, headers=None, payload={},
                 exception=False, content_type=None, count=None):
 
        if isinstance(payload, str):
            payload = [payload]
 
        code = str(code)
 
        if count:
            data_content = {
                'status': status_,                
                'payload': payload,
                'errorBean': [
                {
                    "errorCode": "000",
                    "errorMessage": "000"
                    }
                ]
                
 
            }
        else:
            data_content = {
                'status': status_,
               
                'payload': payload,
                'errorBean': [
                {
                    "errorCode": "000",
                    "errorMessage": "000"
                    }
                ]
                
 
            }
        http_status = get_success_http_status(status)
 
        super(SuccessResponse, self).__init__(
            data=data_content,
            template_name=template_name,
            headers=headers,
            exception=exception,
            content_type=content_type,
            status=http_status
        )
 
 
class ErrorResponse(Response):
 
    def __init__(self, code, msg, status_="ERROR", error_code=rest_status.HTTP_400_BAD_REQUEST, status=rest_status.HTTP_400_BAD_REQUEST,
                template_name=None, headers=None,payload={}, exception=False, content_type=None):
        if isinstance(payload, str):
            payload = [payload]
 
        code = str(code)
 
        data_content = {
            "status": status_,
            "payload": payload,
            "errorBean": [
                {
                "errorCode": code,
                "errorMessage": msg
                }
            ]
        }

           
 
        http_status = get_error_http_status(status)
 
        super(ErrorResponse, self).__init__(
            data=data_content,
            exception=exception,
            template_name=template_name,
            headers=headers,
            content_type=content_type,
            status=http_status
        )
 
 
def is_success_response(response_obj):
    """
    Here we will add system token specific response validation
    It will check success  respone
    It will handle common response modification
    It will check other error condition
    It will trigger add to log message
    """
    resp = response_obj
    resp_json = None
    if resp.status_code == 200 or resp.status_code == 204:
        resp_json = resp.json()
 
    return resp_json
 
 
def pdf_response(is_success, filename=None, result_data=None):
    """
    Args:
        is_success (bool): To check file is created or not
        filename (str, optional): Name of file when downloaded. Defaults to None.
        filepath (str, optional): File path from where file added in response. Defaults to None.
        
    Returns:
        [HttpResponse]: Return response object with status 200 or 503.
    """
    response = None
    if is_success:
        response = HttpResponse(result_data.getvalue(), content_type='application/pdf', status=200)
        response['Content-Disposition'] = 'attachment; filename={}'.format(filename)
    else:
        response = ErrorResponse(msg="PDF Not generated.", code=500,
                                   error_code=rest_status.HTTP_500_INTERNAL_SERVER_ERROR,
                                   status=rest_status.HTTP_500_INTERNAL_SERVER_ERROR)
 
    return response
 
 
def get_success_http_status(status):
    """
    We will map status code in this method
    to return standard http status code.
    """
 
    if isinstance(status, str):
        http_status = rest_status.HTTP_200_OK
    else:
        try:
            http_status = int(status)
            if http_status != 200:
                http_status = rest_status.HTTP_200_OK
        except Exception:
            http_status = rest_status.HTTP_200_OK
    return http_status
 
 
def get_error_http_status(status):
    """
    We will map status code in this method
    to return standard http status code.
    """
 
    if isinstance(status, str):
        http_status = rest_status.HTTP_400_BAD_REQUEST
    else:
        try:
            http_status = int(status)
            if http_status < 500:
                http_status = rest_status.HTTP_400_BAD_REQUEST
            else:
                http_status = rest_status.HTTP_500_INTERNAL_SERVER_ERROR
        except Exception as e:
            http_status = rest_status.HTTP_500_INTERNAL_SERVER_ERROR
 
    return http_status
 
 
# def mf_std_response(code, msg, msg_code, results=[], status=400, error_code=400):
#     if code == 100:
#         return SuccessResponse(msg=msg, results=results, code=code, msg_code=msg_code)
#     else:
#         return ErrorResponse(results=results, msg=msg, code=code, msg_code=msg_code,
#                                status=status, error_code=error_code)
 
 