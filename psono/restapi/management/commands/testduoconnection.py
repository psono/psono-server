from django.core.management.base import BaseCommand

import duo_client
from socket import gaierror
from ssl import SSLError
from urllib.parse import urlencode

class Command(BaseCommand):
    help = 'Tests your ldap config. Requires one user and pass to test login.'

    def add_arguments(self, parser):
        parser.add_argument('integration_key', nargs='+')
        parser.add_argument('secret_key', nargs='+')
        parser.add_argument('host', nargs='+')
        parser.add_argument('username', nargs='+', default='')


    def handle(self, *args, **options):

        integration_key = str(options['integration_key'][0])
        secret_key = str(options['secret_key'][0])
        host = str(options['host'][0])
        username = str(options['username'][0])

        if username:
            print('Testing username format:')
            if '@' not in username:
                error = '  - Error: Username malformed. A real psono username looks similar to an email address.'
                self.stdout.write(error)
                return
            if len(username.split("@")) > 2:
                error = '  - Error: Username malformed. A real psono username looks similar to an email address and may not contain two @ chars.'
                self.stdout.write(error)
                return
            print('  - Success: Username format seems to be correct')


        print('Testing API credentials:')
        try:
            auth_api = duo_client.Auth(
                ikey=integration_key,
                skey=secret_key,
                host=host,
            )

            auth_api.check()
        except gaierror:
            error = '  - Error: Host incorrect: Could not be found'
            self.stdout.write(error)
            return
        except SSLError:
            error = '  - Error: Host incorrect: SSL Certificate Error'
            self.stdout.write(error)
            return
        except RuntimeError as e:
            if 'Invalid integration key' in str(e):
                error = '  - Error: Invalid integration key'
                self.stdout.write(error)
                return
            if 'Invalid signature' in str(e):
                error = '  - Error: Invalid secret key'
                self.stdout.write(error)
                return

            error = str(e)
            self.stdout.write(error)
            return

        print('  - Success: API credentials seem to be correct')

        if username:

            username, domain = username.split("@")

            print('Testing push authentication: ')
            print('Registration of a user / device with QR code on the console would be too hard, therefore we assume '
                  'here that a user with the username "' + username + '" exists and has a device with PUSH support '
                  'registered. If not you can expect this test to fail, yet this failure then would be meaningless. '
                  'You would see some error like: "Received 400 Invalid request parameters (username)"')

            try:
                auth_api = duo_client.Auth(
                    ikey=integration_key,
                    skey=secret_key,
                    host=host,
                )
                auth_api.auth(username=username, factor='push', device='auto', pushinfo=urlencode({'Host': domain}),
                                     passcode=None, async_txn=False)
            except gaierror:
                error = '  - Error: Host incorrect: Could not be found'
                self.stdout.write(error)
                return
            except SSLError:
                error = '  - Error: Host incorrect: SSL Certificate Error'
                self.stdout.write(error)
                return
            except RuntimeError as e:
                if 'Invalid integration key' in str(e):
                    error = '  - Error: Invalid integration key'
                    self.stdout.write(error)
                    return
                if 'Invalid signature' in str(e):
                    error = '  - Error: Invalid secret key'
                    self.stdout.write(error)
                    return

                error = str(e)
                self.stdout.write(error)
                return

            print('  - Success: API credentials seem to be correct')