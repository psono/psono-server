from django.core.management.base import BaseCommand
from django.conf import settings
import nacl.encoding
from nacl.public import PrivateKey
import string
import secrets

from restapi.models import Fileserver_Cluster
from restapi.utils import decrypt_with_db_secret


def show_cluster_config(cluster_id: str) -> dict:

    box = PrivateKey.generate()
    private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
    public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)

    if not cluster_id or cluster_id == 'None':
        return {
            'error': 'CLUSTER_ID required'
        }

    try:
        cluster = Fileserver_Cluster.objects.filter(pk=cluster_id).get()
    except Fileserver_Cluster.DoesNotExist:
        return {
            'error': 'A cluster with this id was not found. You can use "fsclusterlist" to display all'
        }

    if cluster.links.count() == 0:
        return {
            'error': '    Shard: Not found for this cluster. You can create one with "fsshardcreate TITLE \'Some description\'" and then link it to this cluster with "fsshardlink ' + str(
                cluster.id) + ' SHARD_ID"'
        }

    uni = string.ascii_letters + string.digits + string.punctuation

    print('SECRET_KEY: ' + repr((''.join([secrets.choice(uni) for i in range(50)])).replace('\'', '"')))
    print('PRIVATE_KEY: ' + repr(str(private_key_hex.decode())))
    print('PUBLIC_KEY: ' + repr(str(public_key_hex.decode())))
    print('SERVER_URL: ' + repr(settings.HOST_URL))
    print('SERVER_PUBLIC_KEY: ' + repr(settings.PUBLIC_KEY))
    print("CLUSTER_ID: '"+ str(cluster.id) +"'")
    print("CLUSTER_PRIVATE_KEY: '"+ str(decrypt_with_db_secret(cluster.auth_private_key)) +"'")


    shards = []
    for links in cluster.links.all():
        shards.append('{shard_id: ' + str(links.shard_id) + ', read: ' + str(links.read) + ', write: ' + str(links.write) + ', delete: ' + str(links.delete_capability) + ', allow_link_shares: ' + str(links.allow_link_shares) + ', engine: {class: \'local\', kwargs: {location: \'/opt/psono-shard/'+ str(links.shard_id) +'\'}}}')

    print("SHARDS: ["+','.join(shards)+"]")

    return {}

class Command(BaseCommand):
    help = 'Shows the config of cluster members.'
    requires_system_checks = False

    def add_arguments(self, parser):
        parser.add_argument('cluster_id', nargs='?')

    def handle(self, *args, **options):

        cluster_id = str(options['cluster_id'])

        result = show_cluster_config(cluster_id)

        if 'error' in result:
            self.stdout.write(result['error'])
            return



