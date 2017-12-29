from django.core.management.base import BaseCommand

from restapi.utils import disable_user

class Command(BaseCommand):
    help = 'Disable (deactivates) a user'

    def add_arguments(self, parser):
        parser.add_argument('username', nargs='+')


    def handle(self, *args, **options):

        username = str(options['username'][0])

        result = disable_user(username)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        self.stdout.write('Disabled (deactivated) user "' + username + '"' )