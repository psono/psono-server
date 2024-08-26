import bcrypt
from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings

class Command(BaseCommand):
    help = 'Sends a testmail to the specified email address and validates EMAIL_SECRET_SALT'

    def add_arguments(self, parser):
        parser.add_argument('target_email', nargs='+')

    def handle(self, *args, **options):
        target_email = options['target_email'][0]

        try:
            bcrypt.hashpw(target_email.encode(), settings.EMAIL_SECRET_SALT.encode())
        except:
            self.stdout.write('Error EMAIL_SECRET_SALT incorrect. Make sure to use the generateserverkeys command to '
                              'generate it (together with the other parameters). These parameters need to fulfill certain '
                              'constraints and as such cannot be chosen manually.')
            return

        content = 'If you read this, then everything is correctly configured.'

        successful_emails = send_mail(
            'Testmail successfull',
            content,
            settings.EMAIL_FROM,
            [target_email],
            html_message=content,
        )

        if successful_emails > 0:
            self.stdout.write('Successfully sent a testmail to: ' + target_email )
        else:
            self.stdout.write('Error sending the testmail')
