from rest_framework.test import APITestCase
from uuid import UUID
from django.contrib.auth.hashers import make_password

test_authkey = "c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
               "123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
test_authkey_password_hash = make_password(test_authkey)

def is_uuid(expr):
    """
    check if a given expression is a uuid (version 4)

    :param expr: the possible uuid
    :return: True or False
    :rtype: bool
    """

    try:
        val = UUID(expr, version=4)
    except ValueError:
        val = False

    return not not val


class APITestCaseExtended(APITestCase):
    @staticmethod
    def safe_repr(self, obj, short=False):
        _MAX_LENGTH = 80
        try:
            result = repr(obj)
        except Exception:
            result = object.__repr__(obj)
        if not short or len(result) < _MAX_LENGTH:
            return result
        return result[:_MAX_LENGTH] + ' [truncated]...'

    def assertIsUUIDString(self, expr, msg=None):
        """Check that the expression is a valid uuid"""

        if not is_uuid(expr):
            msg = self._formatMessage(msg, "%s is not an uuid" % self.safe_repr(expr))
            raise self.failureException(msg)