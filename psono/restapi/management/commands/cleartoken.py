from django.core.management.base import BaseCommand
from django.utils import timezone
from restapi.models import Token

class Command(BaseCommand):
    help = 'Clears all expired token'

    def handle(self, *args, **options):

        deleted_token = Token.objects.filter(valid_till__lt=timezone.now()).delete()

        self.stdout.write('Cleared token: ' + str(deleted_token[0]))
