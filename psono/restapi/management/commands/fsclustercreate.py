from django.core.management.base import BaseCommand
import nacl.encoding
from nacl.public import PrivateKey
from restapi.models import Fileserver_Cluster
from restapi.utils import encrypt_with_db_secret
import sys


def create_cluster(title: str, file_size_limit=None, fix_cluster_id=None) -> dict:

    box = PrivateKey.generate()
    private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
    public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)

    private_key_hex = encrypt_with_db_secret(private_key_hex.decode())
    public_key_hex = encrypt_with_db_secret(public_key_hex.decode())

    try:
        cluster = Fileserver_Cluster.objects.get(pk=fix_cluster_id)
    except Fileserver_Cluster.DoesNotExist:
        cluster = Fileserver_Cluster.objects.create(
            pk=fix_cluster_id,
            title=title,
            auth_public_key=public_key_hex,
            auth_private_key=private_key_hex,
            file_size_limit=file_size_limit,
        )

    return {
        'cluster': cluster
    }

class Command(BaseCommand):
    help = 'Creates a cluster'
    requires_system_checks = False

    def add_arguments(self, parser):
        parser.add_argument('title', nargs='+')

        parser.add_argument(
            '--file-size-limit',
            type=int,
            default=0,
            dest='file_size_limit',
            help='File size limit in bytes, e.g. 1024 for 1KB',
        )

        parser.add_argument(
            '--fix-cluster-id',
            type=str,
            dest='fix_cluster_id',
            help='A custom fix cluster id. Won\'t create anything if a cluster with this id already exists. e.g. 848b277d-f248-4b5b-83d7-c3c2415fbacf',
        )

        parser.add_argument(
            '--simple-print',
            action='store_true',
            dest='simple_print',
            help='Prints only the new cluster id, e.g. 848b277d-f248-4b5b-83d7-c3c2415fbacf',
        )


    def handle(self, *args, **options):

        title = str(options['title'][0])
        result = create_cluster(title, options['file_size_limit'], options['fix_cluster_id'])

        if 'error' in result:
            self.stdout.write(result['error'])
            sys.exit(1)

        if options['simple_print']:
            print(result['cluster'].id)
        else:
            print('Created. Cluster ID: ' + str(result['cluster'].id))



