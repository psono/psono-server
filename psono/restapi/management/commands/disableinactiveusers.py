from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from restapi.models import User, Token

class Command(BaseCommand):
    help = 'Disable (deactivates) all users that didn\'t login for the past x seconds, e.g. 2592000 for 30 days'

    def add_arguments(self, parser):
        parser.add_argument('seconds', nargs='+')
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Will only report the number of users that would be deactivated.",
        )


    def handle(self, *args, **options):

        seconds = int(options['seconds'][0])

        count = User.objects.filter(last_login__lt=timezone.now() - timedelta(seconds=seconds), is_active=True).count()
        if options["dry_run"]:
            self.stdout.write(f'Disabled inactive users: {count} (dry run)')
            return

        User.objects.filter(last_login__lt=timezone.now() - timedelta(seconds=seconds), is_active=True).update(is_active=False)
        Token.objects.filter(user__in=User.objects.filter(is_active=False)).delete()

        self.stdout.write(f'Disabled inactive users: {count}')