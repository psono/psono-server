from django.core.management.base import BaseCommand
import nacl.encoding
from nacl.public import PrivateKey
import string
import random
import bcrypt

class Command(BaseCommand):
    help = 'Generates a new set of keys that can be used in settings.yml'

    def handle(self, *args, **options):

        uni = string.ascii_letters + string.digits + string.punctuation
        box = PrivateKey.generate()
        private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)

        print('')
        print('# Copy paste this content into your settings.yml and replace existing occurrences')
        print('# ')
        print('# WARNING: Do this only for a fresh installation!')
        print('# Changing those variables afterwards will break the program e.g.:')
        print('# Activation links will not work, Server will not be able to read user emails, ...')
        print('')
        print('SECRET_KEY: ' + repr(''.join([random.SystemRandom().choice(uni) for i in range(50)])))
        print('ACTIVATION_LINK_SECRET: ' + repr(''.join([random.SystemRandom().choice(uni) for i in range(50)])))
        print('DB_SECRET: ' + repr(''.join([random.SystemRandom().choice(uni) for i in range(50)])))
        print('EMAIL_SECRET_SALT: ' + repr(bcrypt.gensalt())).decode()
        print('PRIVATE_KEY: ' + repr(private_key_hex)).decode()
        print('PUBLIC_KEY: ' + repr(public_key_hex)).decode()
        print('')



