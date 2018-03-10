# -*- coding: utf-8 -*-
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from datetime import timedelta
from django.db import IntegrityError
from rest_framework.exceptions import AuthenticationFailed
from ..authentication import TokenAuthentication
from rest_framework import status

from restapi import models

from .base import APITestCaseExtended

from hashlib import sha512
import json
import random
import string
import binascii
import os

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box



class AuthenticationTests(APITestCaseExtended):


    def setUp(self):
        pass


    def test_user_token_to_token_hash(self):
        token = '1234'
        self.assertEqual(TokenAuthentication.user_token_to_token_hash(token), sha512(token.encode()).hexdigest() )



    def test_get_token_hash_success_full(self):

        class Object(object):
            pass

        request = Object()

        request.META = {
            'HTTP_AUTHORIZATION': b'token 1234'
        }

        self.assertEqual(TokenAuthentication.get_token_hash(request), 'd404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db')

    def test_get_token_hash_success_error(self):

        class Object(object):
            pass

        request = Object()

        request.META = {
            'HTTP_AUTHORIZATION': b'123'
        }

        self.assertEqual(TokenAuthentication.get_token_hash(request), None)

    def test_get_token_hash_success_error_no_token_hash(self):

        class Object(object):
            pass

        request = Object()

        request.META = {
            'HTTP_AUTHORIZATION': b'Token '
        }
        try:
            TokenAuthentication.get_token_hash(request)
            self.assertTrue(False, 'get_token_hash should throw an error, so this should not be reached')
        except AuthenticationFailed:
            pass

    def test_get_token_hash_success_error_too_many_spaces(self):

        class Object(object):
            pass

        request = Object()

        request.META = {
            'HTTP_AUTHORIZATION': b'Token 1234 56'
        }
        try:
            TokenAuthentication.get_token_hash(request)
            self.assertTrue(False, 'get_token_hash should throw an error, so this should not be reached')
        except AuthenticationFailed:
            pass


