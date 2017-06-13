from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings

class Command(BaseCommand):
    help = 'Sends a testmail to the specified email address'

    def add_arguments(self, parser):
        parser.add_argument('target_email', nargs='+')

    def handle(self, *args, **options):
        target_email = options['target_email'][0]

        content = 'If you read this, then everything is correctly configured.'

        send_mail(
            'Testmail successfull',
            content,
            settings.EMAIL_FROM,
            [target_email],
            html_message=content,
        )

        self.stdout.write('Successfully sent a testmail to: ' + target_email )