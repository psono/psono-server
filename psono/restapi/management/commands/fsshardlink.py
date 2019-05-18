from django.core.management.base import BaseCommand
from restapi.models import Fileserver_Cluster_Shard_Link
import sys


def link_shard(cluster_id: str, shard_id: str, permission: str, fix_link_id=None) -> dict:

    if not cluster_id or cluster_id == 'None':
        return {
            'error': 'CLUSTER_ID required'
        }

    if not shard_id or shard_id == 'None':
        return {
            'error': 'SHARD_ID required'
        }


    if fix_link_id is None and Fileserver_Cluster_Shard_Link.objects.filter(cluster_id=cluster_id, shard_id=shard_id).count() > 0:
        return {
            'error': 'A link between this shard and cluster already exists'
        }

    try:
        link = Fileserver_Cluster_Shard_Link.objects.get(pk=fix_link_id)
    except Fileserver_Cluster_Shard_Link.DoesNotExist:
        link = Fileserver_Cluster_Shard_Link.objects.create(
            pk=fix_link_id,
            cluster_id=cluster_id,
            shard_id=shard_id,
            read= permission == False or 'r' in permission.lower(),
            write= permission == False or 'w' in permission.lower(),
        )

    return {
        'link': link
    }

class Command(BaseCommand):
    help = 'Links a shard to a cluster'
    requires_system_checks = False

    def add_arguments(self, parser):
        parser.add_argument('cluster_id', nargs='?')
        parser.add_argument('shard_id', nargs='?')
        parser.add_argument('permission', nargs='?', default='rw')

        parser.add_argument(
            '--fix-link-id',
            type=str,
            dest='fix_link_id',
            help='A custom fix link id to use. Won\'t create anything if a link with this id already exists., e.g. 3d594dcb-d14b-4b50-8247-38097ac9a2fd',
        )

        parser.add_argument(
            '--simple-print',
            action='store_true',
            dest='simple_print',
            help='Prints only the new link id, e.g. 3d594dcb-d14b-4b50-8247-38097ac9a2fd',
        )


    def handle(self, *args, **options):

        cluster_id = str(options['cluster_id'])
        shard_id = str(options['shard_id'])
        permission = str(options['permission'])

        result = link_shard(cluster_id, shard_id, permission, options['fix_link_id'])

        if 'error' in result:
            self.stdout.write(result['error'])
            sys.exit(1)

        if options['simple_print']:
            print(result['link'].id)
        else:
            print('Created. Link ID: ' + str(result['link'].id))



