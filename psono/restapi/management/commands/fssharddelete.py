from django.core.management.base import BaseCommand
from restapi.models import Fileserver_Shard
from typing import List


def delete_shard(shard_id: str) -> dict:

    if not shard_id or shard_id == 'None':
        return {
            'error': 'SHARD_ID required'
        }

    try:
        shard = Fileserver_Shard.objects.filter(pk=shard_id).get()
    except Fileserver_Shard.DoesNotExist:
        return {
            'error': 'A shard with this id was not found.'
        }

    shard.delete()

    return {
    }

class Command(BaseCommand):
    help = 'Deletes a shard.'
    requires_system_checks = [] # type: List

    def add_arguments(self, parser):
        parser.add_argument('shard_id', nargs='?')

    def handle(self, *args, **options):

        shard_id = str(options['shard_id'])

        result = delete_shard(shard_id)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        print('Deleted successful.')



