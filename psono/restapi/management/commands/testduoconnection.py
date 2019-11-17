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
            error = 'Host incorrect: Could not be found'
            self.stdout.write(error)
            return
        except SSLError:
            error = 'Host incorrect: SSL Certificate Error'
            self.stdout.write(error)
            return
        except RuntimeError as e:
            if 'Invalid integration key' in str(e):
                error = 'Invalid integration key'
                self.stdout.write(error)
                return
            if 'Invalid signature' in str(e):
                error = 'Invalid secret key'
                self.stdout.write(error)
                return

            error = str(e)
            self.stdout.write(error)
            return

        # Any other error will have be thrown up to now, so reaching this code position means that everything was successful

        print("Success")