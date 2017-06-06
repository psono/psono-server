from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from django.conf import settings
from restapi import models

import pyscrypt
import bcrypt
import hashlib
from restapi.utils import generate_authkey
import os
from nacl.public import PrivateKey, PublicKey, Box
import nacl.secret
import nacl.encoding
import nacl.utils

class Command(BaseCommand):
    help = 'Creates a user with given password'

    def add_arguments(self, parser):
        parser.add_argument('username', nargs='+')
        parser.add_argument('password', nargs='+')
        parser.add_argument('email', nargs='+')


    def encrypt_secret(self, secret, password, user_sauce):
        """
        Encrypts a secret with a password and a random static user specific key we call "user_sauce"
        
        :param secret: The secret to encrypt
        :type secret: str
        :param password: The password to use for the encryption
        :type password: str
        :param user_sauce: A random static user specific key
        :type user_sauce: str
        :return: A tuple of the encrypted secret and nonce
        :rtype: (str, str)
        """

        salt = hashlib.sha512(user_sauce).hexdigest()

        k = hashlib.sha256(pyscrypt.hash(password=password,
                             salt=salt,
                             N=16384,
                             r=8,
                             p=1,
                             dkLen=64).encode('hex')).hexdigest()
        crypto_box = nacl.secret.SecretBox(k, encoder=nacl.encoding.HexEncoder)

        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted_secret_full = crypto_box.encrypt(secret, nonce)
        encrypted_secret = encrypted_secret_full[len(nonce):]

        return nacl.encoding.HexEncoder.encode(encrypted_secret), nacl.encoding.HexEncoder.encode(nonce)


    def handle(self, *args, **options):

        username = str(options['username'][0])
        password = str(options['password'][0])
        email = str(options['email'][0])

        email_bcrypt = bcrypt.hashpw(email, settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)

        if models.User.objects.filter(email_bcrypt=email_bcrypt).exists():
            self.stdout.write('Email already exists.' )
            return

        if models.User.objects.filter(username=username).exists():
            self.stdout.write('Username already exists.' )
            return

        user_sauce = os.urandom(32).encode('hex')
        authkey = make_password(str(generate_authkey(username, password)))

        box = PrivateKey.generate()
        public_key = box.public_key.encode(encoder=nacl.encoding.HexEncoder)
        private_key_decrypted = box.encode(encoder=nacl.encoding.HexEncoder)
        (private_key, private_key_nonce) = self.encrypt_secret(private_key_decrypted, password, user_sauce)

        secret_key_decrypted = os.urandom(32).encode('hex')
        (secret_key, secret_key_nonce) = self.encrypt_secret(secret_key_decrypted, password, user_sauce)


        # normally encrypt emails, so they are not stored in plaintext with a random nonce
        db_secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
        crypto_box = nacl.secret.SecretBox(db_secret_key, encoder=nacl.encoding.HexEncoder)
        encrypted_email = crypto_box.encrypt(email, nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
        email = nacl.encoding.HexEncoder.encode(encrypted_email)

        models.User.objects.create(
            username=username,
            email=email,
            email_bcrypt=email_bcrypt,
            authkey=authkey,
            public_key=public_key,
            private_key=private_key,
            private_key_nonce=private_key_nonce,
            secret_key=secret_key,
            secret_key_nonce=secret_key_nonce,
            is_email_active=True,
            is_active=True,
            user_sauce=user_sauce
        )

        self.stdout.write('Created user "' + username + '" with password "' + password + '" and email "' + email + '"' )