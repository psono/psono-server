from django.core.management import call_command
from django.test import TestCase
from django.conf import settings

from mock import patch, call

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


def fake_send_mail(subject, content, email_from, target_email_list, html_message):
    """
    django.core.mail.send_mail function that wont do anything :)

    :param subject:
    :type subject:
    :param content:
    :type content:
    :param email_from:
    :type email_from:
    :param target_email_list:
    :type target_email_list:
    :param html_message:
    :type html_message:
    :return:
    :rtype:
    """

    return 1


class CommandSendtestmailTestCase(TestCase):

    @patch('django.core.mail.send_mail', side_effect=fake_send_mail)
    def test_sendtestmail(self, fake_send_mail_fct):

        target_email = 'target@example.com'

        args = [target_email]
        opts = {}

        out = StringIO()
        call_command('sendtestmail', stdout=out, *args, **opts)

        self.assertEqual(fake_send_mail_fct.call_count, 1)

        fake_send_mail_fct.assert_has_calls([call('Testmail successfull',
                                                  'If you read this, then everything is correctly configured.',
                                                  settings.EMAIL_FROM, [target_email],
                                                  html_message='If you read this, then everything is correctly configured.')])
