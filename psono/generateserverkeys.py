import nacl.encoding
from nacl.public import PrivateKey
import string
import secrets
import bcrypt

def main():

    uni = string.ascii_letters + string.digits
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
    print('SECRET_KEY: ' + repr((''.join([secrets.choice(uni) for i in range(64)])).replace('\'', '"')))
    print('ACTIVATION_LINK_SECRET: ' + repr((''.join([secrets.choice(uni) for i in range(64)])).replace('\'', '"')))
    print('DB_SECRET: ' + repr((''.join([secrets.choice(uni) for i in range(64)])).replace('\'', '"')))
    print('EMAIL_SECRET_SALT: ' + repr(str(bcrypt.gensalt().decode())))
    print('PRIVATE_KEY: ' + repr(str(private_key_hex.decode())))
    print('PUBLIC_KEY: ' + repr(str(public_key_hex.decode())))
    print('')

if __name__ == '__main__':
    main()


