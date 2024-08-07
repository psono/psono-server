from django.utils.functional import cached_property
from django.core.mail.backends.smtp import EmailBackend
from django.conf import settings
import ssl

class EmailBackendCustomCA(EmailBackend):
    @cached_property
    def ssl_context(self):
        ssl_context = super().ssl_context
        ssl_context.load_verify_locations(cafile=settings.EMAIL_VERIFY_CA_FILE)
        return ssl_context
class EmailBackendNoVerify(EmailBackend):
    @cached_property
    def ssl_context(self):
        ssl_context = super().ssl_context
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context
