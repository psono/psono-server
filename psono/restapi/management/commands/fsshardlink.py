from django.core.management.base import BaseCommand
from restapi.models import Fileserver_Cluster_Shard_Link


def link_shard(cluster_id: str, shard_id: str, permission: str) -> dict:

    if not cluster_id or cluster_id == 'None':
        return {
            'error': 'CLUSTER_ID required'
        }

    if not shard_id or shard_id == 'None':
        return {
            'error': 'SHARD_ID required'
        }


    if Fileserver_Cluster_Shard_Link.objects.filter(cluster_id=cluster_id, shard_id=shard_id).count() > 0:
        return {
            'error': 'A link between this shard and cluster already exists'
        }


    link = Fileserver_Cluster_Shard_Link.objects.create(
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


    def handle(self, *args, **options):

        cluster_id = str(options['cluster_id'])
        shard_id = str(options['shard_id'])
        permission = str(options['permission'])

        print(options)

        result = link_shard(cluster_id, shard_id, permission)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        print('Created. Link ID: ' + str(result['link'].id))



