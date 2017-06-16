from django.core import mail
from django.conf import settings

from .base import APITestCaseExtended

"""
# Tests that don't pass in gitlabs.com's CI / CD

class SystemTests(APITestCaseExtended):
    def test_smtp_server_running(self):
        import socket
        e = None
        try:
            socket.create_connection((settings.EMAIL_HOST, settings.EMAIL_PORT), None)
        except socket.error as e:
            pass

        self.assertIsNone(e, "SMTP server on %s with port %s is not running. The error returnd was %s" % (
        settings.EMAIL_HOST, settings.EMAIL_PORT, str(e)))

    def test_send_email(self):

        mail.outbox = []

        successfull_delivered_messages = mail.send_mail('SMTP e-mail test', 'This is a test e-mail message.',
                                                        'info@psono.pw', ['saschapfeiffer1337@gmail.com'],
                                                        fail_silently=False)

        self.assertEqual(successfull_delivered_messages, 1)

        # Test that one message has been sent.
        self.assertEqual(len(mail.outbox), 1)

        # Verify that the subject of the first message is correct.
        self.assertEqual(mail.outbox[0].subject, 'SMTP e-mail test')

    def test_smtp_credentials(self):

        # TODO write test to check smtp server credentials with SSL / TLS or whatever is configured
        pass

    def test_secret(self):
        secret = settings.SECRET_KEY

        self.assertIsNotNone(secret, 'Please specify a SECRET_KEY that is at least 32 chars long')
        self.assertGreater(len(secret), 0, 'The SECRET_KEY cannot be empty and should have at least 32 chars')
        self.assertGreater(len(secret), 31,
                           'Please use a minimum of 32 chars for the SECRET_KEY, you only have %s' % (len(secret),))
        self.assertNotEqual(secret, 'SOME SUPER SECRET KEY THAT SHOULD BE RANDOM AND 32 OR MORE DIGITS LONG',
                            'Please change the SECRET_KEY value')

    def test_activation_link_secret(self):
        secret = settings.ACTIVATION_LINK_SECRET

        self.assertIsNotNone(secret, 'Please specify a ACTIVATION_LINK_SECRET that is at least 32 chars long')
        self.assertGreater(len(secret), 0,
                           'The ACTIVATION_LINK_SECRET cannot be empty and should have at least 32 chars')
        self.assertGreater(len(secret), 31,
                           'Please use a minimum of 32 chars for the ACTIVATION_LINK_SECRET, you only have %s' % (
                           len(secret),))
        self.assertNotEqual(secret, 'SOME SUPER SECRET KEY THAT SHOULD BE RANDOM AND 32 OR MORE DIGITS LONG',
                            'Please change the ACTIVATION_LINK_SECRET value')

    def test_email_from(self):
        secret = settings.EMAIL_FROM

        self.assertIsNotNone(secret, 'Please specify a EMAIL_FROM settings value')
        self.assertGreater(len(secret), 0, 'Please specify a EMAIL_FROM settings value')
        self.assertNotEqual(secret, 'the-mail-for-for-example-useraccount-activations@test.com',
                            'Please change the EMAIL_FROM value')
"""










