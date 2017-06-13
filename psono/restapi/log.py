import logging
import datetime
import re

from six import iteritems
from django.conf import settings
from django.core.management.color import color_style

class AuditFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        self.style = color_style()
        super(AuditFormatter, self).__init__(*args, **kwargs)

    def escape(self, string):
        string = str(string)
        string = string.replace("\\", "\\\\")
        string = string.replace("\"", "\\\"")
        if re.search(r"\s", string):
            return '"'+string+'"'
        return string

    def format(self, record):

        new_message = []
        for (key, value) in iteritems(record.msg):
            new_message.append(self.escape(key) + '=' + self.escape(value))

        record.msg = ", ".join(new_message)
        record.time_utc = datetime.datetime.utcnow().isoformat()
        record.time_server = datetime.datetime.now().isoformat()

        return super(AuditFormatter, self).format(record)

class FilterConsole(logging.Filter):
    def filter(self, record):
        return settings.DEBUG and settings.LOGGING_AUDIT

class FilterFile(logging.Filter):
    def filter(self, record):
        return not settings.DEBUG and settings.LOGGING_AUDIT