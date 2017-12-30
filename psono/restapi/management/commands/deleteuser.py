from django.core.management.base import BaseCommand

from restapi.utils import delete_user

class Command(BaseCommand):
    help = 'Deletes a user'

    def add_arguments(self, parser):
        parser.add_argument('username', nargs='+')


    def handle(self, *args, **options):

        username = str(options['username'][0])

        result = delete_user(username)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        self.stdout.write('Deleted user "' + username + '"' )