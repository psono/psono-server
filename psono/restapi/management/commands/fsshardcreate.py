from django.core.management.base import BaseCommand
from restapi.models import Fileserver_Shard
import sys
from typing import List


def create_shard(title: str, description: str, fix_shard_id=None) -> dict:

    try:
        shard = Fileserver_Shard.objects.get(pk=fix_shard_id)
    except Fileserver_Shard.DoesNotExist:
        shard = Fileserver_Shard.objects.create(
            pk=fix_shard_id,
            title=title,
            description=description,
        )

    return {
        'shard': shard
    }

class Command(BaseCommand):
    help = 'Creates a shard'
    requires_system_checks = [] # type: List

    def add_arguments(self, parser):
        parser.add_argument('title', nargs='+')
        parser.add_argument('description', nargs='+')

        parser.add_argument(
            '--fix-shard-id',
            type=str,
            dest='fix_shard_id',
            help='A custom fix shard id to use. Won\'t create anything if a shard with this id already exists., e.g. 3d594dcb-d14b-4b50-8247-38097ac9a2fd',
        )

        parser.add_argument(
            '--simple-print',
            action='store_true',
            dest='simple_print',
            help='Prints only the new shard id, e.g. 3d594dcb-d14b-4b50-8247-38097ac9a2fd',
        )


    def handle(self, *args, **options):

        title = str(options['title'][0])
        description = str(options['description'][0])

        result = create_shard(title, description, options['fix_shard_id'])

        if 'error' in result:
            self.stdout.write(result['error'])
            sys.exit(1)

        if options['simple_print']:
            print(result['shard'].id)
        else:
            print('Created. Shard ID: ' + str(result['shard'].id))



