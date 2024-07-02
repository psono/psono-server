from django.conf import settings
import requests

def ivalt_auth_request_sent(mobile: str) -> dict:
     # send notification to user's mobile to authenticate
    url = "https://api.ivalt.com/biometric-auth-request"
    headers = {
        "x-api-key": settings.IVALT_SECRET_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "mobile": mobile
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
        response = response.json()
        message = response.get("message")
        if message:
            return {
                'error': 'Invalid secret key'
            }
        return response
    except requests.exceptions.Timeout:
        return {
                'error': 'Request timed out'
            }
    except requests.exceptions.RequestException as e:
        return {
                'error': str(e)
            }

def ivalt_auth_request_verify(mobile: str) -> dict:
     # verify user's mobile to authenticate
    url = "https://api.ivalt.com/biometric-geo-fence-auth-results"
    headers = {
        "x-api-key": settings.IVALT_SECRET_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "mobile": mobile
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
        response = response.json()
        message = response.get("message")
        if message:
            return {
                'error': 'Invalid secret key'
            }
        return response
    except requests.exceptions.Timeout:
        return {
                'error': 'Request timed out'
            }
    except requests.exceptions.RequestException as e:
        return {
                'error': str(e)
            }