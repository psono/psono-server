from django.utils.functional import cached_property
from django.core.mail.backends.smtp import EmailBackend
from django.conf import settings

class CustomCAEmailBackend(EmailBackend):
    @cached_property
    def ssl_context(self):
        ssl_context = super().ssl_context
        ssl_context.load_verify_locations(cafile=settings.EMAIL_VERIFY_CA_FILE)
        return ssl_context
