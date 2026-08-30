from django.core.management.base import BaseCommand
from generateserverkeys import main as generateserverkeys


class Command(BaseCommand):
    help = "Generates server settings keys and an offline admin recovery keypair"

    def handle(self, *args, **options):

        generateserverkeys()
