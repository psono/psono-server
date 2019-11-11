import duo_client
from socket import gaierror
from ssl import SSLError
from typing import Dict

def duo_auth_check(integration_key: str, secret_key: str, host: str) -> dict:
    """
    Calls the Duo auth check api

    :param integration_key: The Duo integration key
    :type integration_key:  str
    :param secret_key: The Duo secret key
    :type secret_key: str
    :param host: The Duo host
    :type host: str
    :return: The check with the error details or the time
    :rtype: dict
    """

    try:
        auth_api = duo_client.Auth(
            ikey=integration_key,
            skey=secret_key,
            host=host,
        )
        check = auth_api.check()
    except gaierror:
        return {
            'error': 'Host incorrect: Could not be found'
        }
    except SSLError:
        return {
            'error': 'Host incorrect: SSL Certificate Error'
        }
    except RuntimeError as e:
        if 'Invalid integration key' in str(e):
            return {
                'error': 'Invalid integration key'
            }
        if 'Invalid signature' in str(e):
            return {
                'error': 'Invalid secret key'
            }

        return {
            'error': str(e)
        }

    except:
        return {
            'error': 'Duo offline. Try again later.'
        }

    return check


def duo_auth_enroll(integration_key: str, secret_key: str, host: str, username: str) -> dict:
    """
    Anonymous enrollment of a new device

    :param integration_key: The Duo integration key
    :type integration_key:  str
    :param secret_key: The Duo secret key
    :type secret_key: str
    :param host: The Duo host
    :type host: str
    :param username: The Duo host
    :type username: str
    :return: The check with the error details or the time
    :rtype: dict
    """

    try:
        auth_api = duo_client.Auth(
            ikey=integration_key,
            skey=secret_key,
            host=host,
        )

        pre_auth = auth_api.preauth(username=username)

        if pre_auth['result'] == 'deny':
            return {
                'error': 'User denied by DUO'
            }

        enrollment = {} # type: Dict
        if pre_auth['result'] == 'enroll':
            enrollment = auth_api.enroll(username=username)

    except gaierror:
        return {
            'error': 'Host incorrect: Could not be found'
        }
    except SSLError:
        return {
            'error': 'Host incorrect: SSL Certificate Error'
        }
    except RuntimeError as e:
        if 'Invalid integration key' in str(e):
            return {
                'error': 'Invalid integration key'
            }
        if 'Invalid signature' in str(e):
            return {
                'error': 'Invalid secret key'
            }
        if 'username already exists' in str(e):
            return {
                'error': 'Username already exists in Duo.'
            }

        return {
            'error': str(e)
        }

    except:
        return {
            'error': 'Duo offline. Try again later.'
        }

    return enrollment


def duo_auth_enroll_status(integration_key: str, secret_key: str, host: str, user_id: str, activation_code: str) -> dict:
    """
    Anonymous enrollment of a new device

    :param integration_key: The Duo integration key
    :type integration_key:  str
    :param secret_key: The Duo secret key
    :type secret_key: str
    :param host: The Duo host
    :type host: str
    :param user_id: The Duo user id
    :type user_id: str
    :param activation_code: The Duo activation code
    :type activation_code: str
    :return: The check with the error details or the time
    :rtype: dict
    """

    try:
        auth_api = duo_client.Auth(
            ikey=integration_key,
            skey=secret_key,
            host=host,
        )


        enrollment_status = auth_api.enroll_status(user_id=user_id, activation_code=activation_code)
    except gaierror:
        return {
            'error': 'Host incorrect: Could not be found'
        }
    except SSLError:
        return {
            'error': 'Host incorrect: SSL Certificate Error'
        }
    except RuntimeError as e:
        if 'Invalid integration key' in str(e):
            return {
                'error': 'Invalid integration key'
            }
        if 'Invalid signature' in str(e):
            return {
                'error': 'Invalid secret key'
            }

        return {
            'error': str(e)
        }

    except:
        return {
            'error': 'Duo offline. Try again later.'
        }

    return enrollment_status




def duo_auth_auth(integration_key: str, secret_key: str, host: str, username: str, factor: str, device: str = None, pushinfo: str = None, passcode: str = None, async: bool = False) -> dict:
    """
    Auth call with the user id

    :param integration_key: The Duo integration key
    :type integration_key:  str
    :param secret_key: The Duo secret key
    :type secret_key: str
    :param host: The Duo host
    :type host: str
    :param username: The Duo username
    :type username: str
    :param factor: The Duo factor
    :type factor: str
    :param device: The Duo device
    :type device: str
    :param pushinfo: The pushinfo
    :type pushinfo: str
    :param passcode: The passcode
    :type passcode: str
    :param async: The Duo async flag
    :type async: bool
    :return: The check with the error details or the time
    :rtype: dict
    """

    try:
        auth_api = duo_client.Auth(
            ikey=integration_key,
            skey=secret_key,
            host=host,
        )
        auth = auth_api.auth(username=username, factor=factor, device=device, pushinfo=pushinfo, passcode=passcode, async=async)
    except gaierror:
        return {
            'error': 'Host incorrect: Could not be found'
        }
    except SSLError:
        return {
            'error': 'Host incorrect: SSL Certificate Error'
        }
    except RuntimeError as e:
        if 'Invalid integration key' in str(e):
            return {
                'error': 'Invalid integration key'
            }
        if 'Invalid signature' in str(e):
            return {
                'error': 'Invalid secret key'
            }

        return {
            'error': str(e)
        }

    except:
        return {
            'error': 'Duo offline. Try again later.'
        }

    return auth

