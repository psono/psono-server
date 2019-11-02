from django.core.management.base import BaseCommand
from django.db.models import Exists, OuterRef
from django.utils import timezone
from restapi.models import Token, Secret, Secret_Link, Link_Share

class Command(BaseCommand):
    help = 'Clears expired token and objects (shares, secrets, ...) without reference'

    def handle(self, *args, **options):

        Token.objects.filter(valid_till__lt=timezone.now()).delete()

        secret_links = Secret_Link.objects.filter(
            secret = OuterRef('pk'),
        )
        Secret.objects.annotate(
            has_secret_link = ~Exists(secret_links),
        ).filter(has_secret_link=True).delete()

        Link_Share.objects.filter(valid_till__lt=timezone.now()).delete()

        self.stdout.write('Done' )
