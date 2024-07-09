from django.test import TestCase
from mock import patch, Mock
import requests
from restapi.utils import ivalt_auth_request_sent, ivalt_auth_request_verify

class TestIvaltAuthRequestSentUtils(TestCase):

    @patch('restapi.utils.ivalt.requests.post')
    def test_ivalt_auth_request_sent_success(self, mock_post):
        # Mock a successful response from the third-party API
        mock_response = Mock()
        mock_response.json.return_value = {"data": {"status": True, "message": "Biometric Auth Request successfully sent.", "details": None }}
        mock_response.get.return_value = None  # No 'message' key in the response
        mock_post.return_value = mock_response

        response = ivalt_auth_request_sent("+10123456789")
        self.assertEqual(response, {"data": {"status": True, "message": "Biometric Auth Request successfully sent.", "details": None }})
    
    @patch('restapi.utils.ivalt.requests.post')
    def test_ivalt_auth_request_sent_invalid_secret_key(self, mock_post):
        # Mock a response with an error message
        mock_response = Mock()
        mock_response.json.return_value = {"message": "Invalid secret key"}
        mock_response.get.return_value = "Invalid secret key"
        mock_post.return_value = mock_response

        response = ivalt_auth_request_sent("+10123456789")
        self.assertEqual(response, {'error': 'Invalid secret key'})

    @patch('restapi.utils.ivalt.requests.post')
    def test_ivalt_auth_request_sent_exception(self, mock_post):
        # Mock a request exception
        mock_post.side_effect = requests.exceptions.RequestException("Internal server error")

        response = ivalt_auth_request_sent("+10123456789")
        self.assertEqual(response, {'error': 'Internal server error'})

class TestIvaltAuthRequestVerifyUtils(TestCase):

    @patch('restapi.utils.ivalt.requests.post')
    def test_ivalt_auth_request_verify_success(self, mock_post):
        # Mock a successful response from the third-party API
        mock_response = Mock()
        mock_response.json.return_value = {"data": { "status": True, "message": "Biometric Authentication successfully done.", "details": { "id": 1111, "name": "user_name", "email": "user_email", "country_code": "country_code", "mobile": "user_mobile", "latitude": "latitude", "longitude": "longitude", "imei": "imei", "address": "user_address" }}}
        mock_response.get.return_value = None  # No 'message' key in the response
        mock_post.return_value = mock_response

        response = ivalt_auth_request_verify("+10123456789")
        self.assertEqual(response, {"data": { "status": True, "message": "Biometric Authentication successfully done.", "details": { "id": 1111, "name": "user_name", "email": "user_email", "country_code": "country_code", "mobile": "user_mobile", "latitude": "latitude", "longitude": "longitude", "imei": "imei", "address": "user_address" }}})
    
    @patch('restapi.utils.ivalt.requests.post')
    def test_ivalt_auth_request_verify_invalid_secret_key(self, mock_post):
        # Mock a response with an error message
        mock_response = Mock()
        mock_response.json.return_value = {"message": "Invalid secret key"}
        mock_response.get.return_value = "Invalid secret key"
        mock_post.return_value = mock_response

        response = ivalt_auth_request_verify("+10123456789")
        self.assertEqual(response, {'error': 'Invalid secret key'})

    @patch('restapi.utils.ivalt.requests.post')
    def test_ivalt_auth_request_verify_exception(self, mock_post):
        # Mock a request exception
        mock_post.side_effect = requests.exceptions.RequestException("Internal server error")

        response = ivalt_auth_request_verify("+10123456789")
        self.assertEqual(response, {'error': 'Internal server error'})