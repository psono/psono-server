from django.core.management.base import BaseCommand
from restapi.models import Fileserver_Shard
from typing import List


class Command(BaseCommand):
    help = 'Lists all shards'
    requires_system_checks = [] # type: List

    def handle(self, *args, **options):

        shards = Fileserver_Shard.objects.all()

        if len(shards) == 0:
            print('No shards found. You can create one with "fsshardcreate TITLE \'Some description\'"')

        for shard in shards:
            print('Shard: ' + str(shard.title) + ' (ID: ' + str(shard.id) + ')')

            if shard.links.count() == 0:
                print('    Cluster: Not linked to any cluster. You can create a link with "fsshardlink CLUSTER_ID '+ str(shard.id) +'"')

            for links in shard.links.all():
                print('    Cluster: ' + str(links.cluster.title) + ' (link_id: ' + str(links.id) + ', cluster_id: ' + str(links.cluster_id) + ', read: ' + str(links.read) + ', write: ' + str(links.write) + ')')



