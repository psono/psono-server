from django.core.management.base import BaseCommand
from restapi.models import Fileserver_Cluster


def delete_cluster(cluster_id: str) -> dict:

    if not cluster_id or cluster_id == 'None':
        return {
            'error': 'CLUSTER_ID required'
        }

    try:
        cluster = Fileserver_Cluster.objects.filter(pk=cluster_id).get()
    except Fileserver_Cluster.DoesNotExist:
        return {
            'error': 'A cluster with this id was not found.'
        }

    cluster.delete()

    return {
    }

class Command(BaseCommand):
    help = 'Deletes a cluster.'
    requires_system_checks = False

    def add_arguments(self, parser):
        parser.add_argument('cluster_id', nargs='?')

    def handle(self, *args, **options):

        cluster_id = str(options['cluster_id'])

        result = delete_cluster(cluster_id)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        print('Deleted successful.')



