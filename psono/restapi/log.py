import logging
import datetime
import re

from django.conf import settings
from django.core.management.color import color_style

class QueryFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        self.style = color_style()
        super(QueryFormatter, self).__init__(*args, **kwargs)

    def escape(self, string):
        string = str(string)
        string = string.replace("\\", "\\\\")
        string = string.replace("\"", "\\\"")
        if re.search(r"\s", string):
            return '"'+string+'"'
        return string

    def format(self, record):

        new_message = []

        new_message.append('duration=' + self.escape(str(record.args[0])))
        new_message.append('sql=' + self.escape(str(record.args[1])))

        record.msg = ", ".join(new_message)
        record.time_utc = datetime.datetime.utcnow().isoformat()
        record.time_server = datetime.datetime.now().isoformat()
        record.args = []

        return super(QueryFormatter, self).format(record)


class FilterQueryConsole(logging.Filter):
    def filter(self, record):
        return settings.DEBUG
