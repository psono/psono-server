from uuid import UUID
from rest_framework.test import APITestCase

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

    def assertIsUUIDString(self, expr, msg):
        """Check that the expression is a valid uuid"""

        try:
            val = UUID(expr, version=4)
        except ValueError:
            val = False

        if not val:
            msg = self._formatMessage(msg, "%s is not an uuid" % self.safe_repr(expr))
            raise self.failureException(msg)