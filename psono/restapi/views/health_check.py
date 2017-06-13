from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from django.db import connection
from django.conf import settings

from django.db.migrations.executor import MigrationExecutor
from django.db import connections, DEFAULT_DB_ALIAS

import ntplib


class HealthCheckView(GenericAPIView):
    permission_classes = (AllowAny,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')
    throttle_scope = 'health_check'

    def get(self, request, *args, **kwargs):
        """
        Check the health of the application
        
        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        unhealthy = False

        db_read = True
        db_sync = True
        time_sync = True

        def db_read_unhealthy():

            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1", [])
                    cursor.fetchone()
            except:
                return True

            return False

        def db_sync_unhealthy():
            try:
                connection = connections[DEFAULT_DB_ALIAS]
                connection.prepare_database()
                executor = MigrationExecutor(connection)
                targets = executor.loader.graph.leaf_nodes()
            except:
                return True

            return len(executor.migration_plan(targets)) > 0

        def time_sync_unhealthy():
            c = ntplib.NTPClient()
            response = c.request(settings.TIME_SERVER, version=3)
            return abs(response.offset) > 1

        if db_read_unhealthy():
            unhealthy = True
            db_read = False

        if db_sync_unhealthy():
            unhealthy = True
            db_sync = False

        if time_sync_unhealthy():
            unhealthy = True
            time_sync = False

        if unhealthy:
            health_status = status.HTTP_400_BAD_REQUEST
        else:
            health_status = status.HTTP_200_OK


        return Response({
            'db_read': { 'healthy': db_read },
            'db_sync': { 'healthy': db_sync },
            'time_sync': { 'healthy': time_sync },
        }, status=health_status)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)