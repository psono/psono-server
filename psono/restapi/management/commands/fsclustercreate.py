from django.core.management.base import BaseCommand
import nacl.encoding
from nacl.public import PrivateKey
from restapi.models import Fileserver_Cluster
from restapi.utils import encrypt_with_db_secret


def create_cluster(title: str, file_size_limit) -> dict:

    box = PrivateKey.generate()
    private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
    public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)

    private_key_hex = encrypt_with_db_secret(private_key_hex.decode())
    public_key_hex = encrypt_with_db_secret(public_key_hex.decode())


    Fileserver_Cluster.objects.create(
        title=title,
        auth_public_key=public_key_hex,
        auth_private_key=private_key_hex,
        file_size_limit=file_size_limit,
    )

    return {}

class Command(BaseCommand):
    help = 'Creates a cluster'
    requires_system_checks = False

    def add_arguments(self, parser):
        parser.add_argument('title', nargs='+')

        # Named (optional) arguments
        parser.add_argument(
            '--file-size-limit',
            action='store_true',
            dest='file_size_limit',
            help='File size limit in bytes, e.g. 1024 for 1KB',
        )


    def handle(self, *args, **options):

        title = str(options['title'][0])

        result = create_cluster(title, options['file_size_limit'])

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        print('Created.')



