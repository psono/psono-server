from django.core.management.base import BaseCommand
from generateserverkeys import main as generateserverkeys

class Command(BaseCommand):
    help = 'Generates a new set of keys that can be used in settings.yml'

    def handle(self, *args, **options):

        generateserverkeys()



