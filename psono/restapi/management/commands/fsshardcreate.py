from django.core.management.base import BaseCommand
from restapi.models import Fileserver_Shard


def create_shard(title: str, description: str) -> dict:

    shard = Fileserver_Shard.objects.create(
        title=title,
        description=description,
    )

    return {
        'shard': shard
    }

class Command(BaseCommand):
    help = 'Creates a shard'
    requires_system_checks = False

    def add_arguments(self, parser):
        parser.add_argument('title', nargs='+')
        parser.add_argument('description', nargs='+')


    def handle(self, *args, **options):

        title = str(options['title'][0])
        description = str(options['description'][0])

        result = create_shard(title, description)

        if 'error' in result:
            self.stdout.write(result['error'])
            return

        print('Created. Shard ID: ' + str(result['shard'].id))



