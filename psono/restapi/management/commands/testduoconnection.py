from django.core.management.base import BaseCommand

import duo_client
from socket import gaierror
from ssl import SSLError

class Command(BaseCommand):
    help = 'Tests your ldap config. Requires one user and pass to test login.'

    def add_arguments(self, parser):
        parser.add_argument('integration_key', nargs='+')
        parser.add_argument('secret_key', nargs='+')
        parser.add_argument('host', nargs='+')


    def handle(self, *args, **options):

        integration_key = str(options['integration_key'][0])
        secret_key = str(options['secret_key'][0])
        host = str(options['host'][0])

        try:
            auth_api = duo_client.Auth(
                ikey=integration_key,
                skey=secret_key,
                host=host,
            )

            auth_api.check()
        except gaierror:
            self.stdout.write('Host incorrect: Could not be found')
            return
        except SSLError:
            self.stdout.write('Host incorrect: SSL Certificate Error')
            return
        except RuntimeError as e:
            if 'Invalid integration key' in str(e):
                self.stdout.write('Invalid integration key')
                return
            if 'Invalid signature' in str(e):
                self.stdout.write('Invalid secret key')
                return

            self.stdout.write(str(e))
            return

        # Any other error will have be thrown up to now, so reaching this code position means that everything was successful

        print("Success")