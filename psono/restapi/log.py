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

class QueryFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        self.style = color_style()
        super(QueryFormatter, self).__init__(*args, **kwargs)

    def escape(self, string):
        string = str(string)
        string = string.replace("\\", "\\\\")
        string = string.replace("\"", "\\\"")
        string = string.replace('\n', '\\n')
        if re.search(r"\s", string):
            return '"'+string+'"'
        return string

    def format(self, record):

        new_message = []

        new_message.append('duration=' + self.escape(str(record.args[0])))
        new_message.append('sql=' + self.escape(str(record.args[1])))
        # new_message.append('params=' + self.escape(str(record.args[2])))

        record.msg = ", ".join(new_message)
        record.time_utc = datetime.datetime.utcnow().isoformat()
        record.time_server = datetime.datetime.now().isoformat()
        record.args = []

        return super(QueryFormatter, self).format(record)

class FilterAuditConsole(logging.Filter):
    def filter(self, record):
        return settings.DEBUG and settings.LOGGING_AUDIT

class FilterAuditFile(logging.Filter):
    def filter(self, record):
        return not settings.DEBUG and settings.LOGGING_AUDIT

class FilterQueryConsole(logging.Filter):
    def filter(self, record):
        return settings.DEBUG and settings.LOGGING_QUERY

class FilterQueryFile(logging.Filter):
    def filter(self, record):
        return not settings.DEBUG and settings.LOGGING_QUERY