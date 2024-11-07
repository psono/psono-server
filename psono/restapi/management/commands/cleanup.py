from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db.models import Exists, OuterRef
from django.utils import timezone
from restapi.models import Token
from restapi.models import Secret
from restapi.models import Secret_Link
from restapi.models import Share_Tree
from restapi.models import Link_Share
from restapi.models import Share

class Command(BaseCommand):
    help = 'Clears expired token and objects (shares, secrets, ...) without reference'

    def handle(self, *args, **options):

        Token.objects.filter(valid_till__lt=timezone.now()).delete()

        secret_links = Secret_Link.objects.filter(
            secret = OuterRef('pk'),
        )
        Secret.objects.annotate(
            has_secret_link = Exists(secret_links),
        ).filter(has_secret_link=False).delete()

        Link_Share.objects.filter(valid_till__lt=timezone.now()).delete()

        share_tree = Share_Tree.objects.filter(
            share = OuterRef('pk'),
        )
        Share.objects.annotate(
            has_share_tree_entry = Exists(share_tree),
        ).filter(
            has_share_tree_entry=False,
            create_date__lt=timezone.now() - timedelta(days=28)
        ).delete()

        self.stdout.write('Done' )
