import logging

from django.conf import settings
from django.core.management.color import color_style

class AuditFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        self.style = color_style()
        super(AuditFormatter, self).__init__(*args, **kwargs)

    def format(self, record):
        msg = record.msg

        record.msg = msg

        return super(AuditFormatter, self).format(record)

class FilterConsole(logging.Filter):
    def filter(self, record):
        return settings.DEBUG and settings.LOGGING_AUDIT

class FilterFile(logging.Filter):
    def filter(self, record):
        return not settings.DEBUG and settings.LOGGING_AUDIT