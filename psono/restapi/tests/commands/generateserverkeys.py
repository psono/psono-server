from django.core.management import call_command
from django.test import TestCase

from io import StringIO


class CommandGenerateserverkeysTestCase(TestCase):

    def test_generateserverkeys(self):

        args = []
        opts = {}

        out = StringIO()
        call_command('generateserverkeys', stdout=out, *args, **opts)