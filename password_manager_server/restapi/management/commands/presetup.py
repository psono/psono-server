from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = 'Setups all pre requirements'

    def handle(self, *args, **options):
        cursor = connection.cursor()
        cursor.execute('''CREATE EXTENSION IF NOT EXISTS ltree''')
        self.stdout.write('success: CREATE EXTENSION IF NOT EXISTS ltree' )