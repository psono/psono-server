from django.core.management.base import BaseCommand
from restapi.models import Fileserver_Cluster


class Command(BaseCommand):
    help = 'Lists all clusters'
    requires_system_checks = False

    def handle(self, *args, **options):

        clusters = Fileserver_Cluster.objects.all()

        if len(clusters) == 0:
            print('No cluster found. You can create one with "fsclustercreate TITLE"')

        for cluster in clusters:
            print('Cluster: ' + str(cluster.title) + ' (ID: ' + str(cluster.id) + ')')

            if cluster.links.count() == 0:
                print('    Shard: Not found for this cluster. You can create one with "fsshardcreate TITLE \'Some description\'" and then link it to this cluster with "fsshardlink '+ str(cluster.id) +' SHARD_ID"')

            for links in cluster.links.all():
                print('    Shard: ' + str(links.shard.title) + ' (link_id: ' + str(links.id) + ', shard_id: ' + str(links.shard_id) + ', read: ' + str(links.read) + ', write: ' + str(links.write) + ')')



