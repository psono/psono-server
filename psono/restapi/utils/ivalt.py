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
    except:
        return False
    
    if response.status_code != 200:
        return False
    
    return True

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
    except:
        return False, None
    
    if response.status_code != 200:
        response = response.json()
        if 'timezone' in response.get('error', {}).get('detail', ''):
            return False, 'INVALID_TIMEZONE'
        if 'geofencing' in response.get('error', {}).get('detail', ''):
            return False, 'INVALID_GEOFENCE'
        return False, None

    return True, None
