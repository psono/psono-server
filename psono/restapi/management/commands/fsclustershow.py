from typing import List

from django.core.management.base import BaseCommand

from restapi.models import Fileserver_Cluster


class Command(BaseCommand):
    help = "Shows all file-server clusters"
    requires_system_checks = []  # type: List

    def handle(self, *args, **options):
        clusters = Fileserver_Cluster.objects.order_by("title", "id").values_list(
            "title", "id"
        )

        for title, cluster_id in clusters:
            self.stdout.write(f"Cluster: {title} (ID: {cluster_id})")
