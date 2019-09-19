from django.core.management.base import BaseCommand

from restapi.utils import verify_user_email

class Command(BaseCommand):
    help = 'Marks the email address of a user as verified'

    def add_arguments(self, parser):
        parser.add_argument('username', nargs='+')


    def handle(self, *args, **options):

        username = str(options['username'][0])

        result = verify_user_email(username)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        self.stdout.write('Verified the email of user "' + username + '"' )