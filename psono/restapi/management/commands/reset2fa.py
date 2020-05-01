from django.core.management.base import BaseCommand

from restapi.utils import reset_2fa

class Command(BaseCommand):
    help = 'Resets 2FA of a user'

    def add_arguments(self, parser):
        parser.add_argument('username', nargs='+')


    def handle(self, *args, **options):

        username = str(options['username'][0])

        result = reset_2fa(username)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        self.stdout.write('Reset two factor authentication of user "' + username + '"')
