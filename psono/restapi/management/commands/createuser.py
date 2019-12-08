from django.core.management.base import BaseCommand

from restapi.utils import create_user

class Command(BaseCommand):
    help = 'Creates a user with given password'

    def add_arguments(self, parser):
        parser.add_argument('username', nargs='+')
        parser.add_argument('password', nargs='+')
        parser.add_argument('email', nargs='+')

        parser.add_argument(
            '--show-password',
            action='store_true',
            dest='show_password',
            help='Shows the password in the completion success message in plain text',
        )


    def handle(self, *args, **options):

        username = str(options['username'][0])
        password = str(options['password'][0])
        email = str(options['email'][0])

        result = create_user(username, password, email)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        if not options['show_password']:
            password = '******'

        self.stdout.write('Created user "' + username + '" with password "' + password + '" and email "' + email + '"' )