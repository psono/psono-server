from django.core.management.base import BaseCommand
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from restapi.models import Token

class Command(BaseCommand):
    help = 'Clears all expired token'

    def handle(self, *args, **options):
        time_threshold = timezone.now() - timedelta(seconds=settings.TOKEN_TIME_VALID)

        Token.objects.filter(create_date__lt=time_threshold).delete()

        self.stdout.write('Successfully cleared token' )