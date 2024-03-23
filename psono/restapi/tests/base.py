import hashlib
from rest_framework.test import APITestCase
from uuid import UUID
from django.contrib.auth.hashers import BasePasswordHasher

class InsecureUnittestPasswordHasher(BasePasswordHasher):
    """
    The Salted MD5 password hashing algorithm (not recommended) and only used for unittests to speed them up
    """

    algorithm = "md5"

    def encode(self, password, salt):
        self._check_encode_args(password, salt)
        hash = hashlib.md5((salt + password).encode()).hexdigest()
        return "%s$%s$%s" % (self.algorithm, salt, hash)

    def decode(self, encoded):
        algorithm, salt, hash = encoded.split("$", 2)
        assert algorithm == self.algorithm
        return {
            "algorithm": algorithm,
            "hash": hash,
            "salt": salt,
        }

    def verify(self, password, encoded):
        decoded = self.decode(encoded)
        encoded_2 = self.encode(password, decoded["salt"])
        return encoded == encoded_2

    def safe_summary(self, encoded):
        decoded = self.decode(encoded)
        return {
            _("algorithm"): decoded["algorithm"],
            _("salt"): mask_hash(decoded["salt"], show=2),
            _("hash"): mask_hash(decoded["hash"]),
        }

    def must_update(self, encoded):
        return False

    def harden_runtime(self, password, encoded):
        pass

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