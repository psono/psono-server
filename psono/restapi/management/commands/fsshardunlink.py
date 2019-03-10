from django.core.management.base import BaseCommand
from restapi.models import Fileserver_Cluster_Shard_Link


def unlink_shard(link_id: str) -> dict:

    if not link_id or link_id == 'None':
        return {
            'error': 'LINK_ID required'
        }

    try:
        link = Fileserver_Cluster_Shard_Link.objects.filter(pk=link_id).get()
    except Fileserver_Cluster_Shard_Link.DoesNotExist:
        return {
            'error': 'A link with this id was not found.'
        }

    link.delete()

    return {
    }

class Command(BaseCommand):
    help = 'Unlinks a shard from a cluster'
    requires_system_checks = False

    def add_arguments(self, parser):
        parser.add_argument('link_id', nargs='?')


    def handle(self, *args, **options):

        link_id = str(options['link_id'])

        result = unlink_shard(link_id)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        print('Deleted successful.')



