from django.core.management.base import BaseCommand

from restapi.utils import demmote_user

class Command(BaseCommand):
    help = 'Demotes a user'

    def add_arguments(self, parser):
        parser.add_argument('username', nargs='+')
        parser.add_argument('role', nargs='+')


    def handle(self, *args, **options):

        username = str(options['username'][0])
        role = str(options['role'][0])

        result = demmote_user(username, role)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        self.stdout.write('Demoted user "' + username + '" and removed "' + role + '"' )