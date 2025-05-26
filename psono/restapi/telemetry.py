import uuid
import os
from operator import attrgetter
from opentelemetry import trace, baggage, context
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.django import DjangoInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import get_current_span
from django.conf import settings

def is_opentelemetry_enabled():
    return bool(os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", ""))

def setup_telemetry():
    if not is_opentelemetry_enabled():
        return
    trace_provider = TracerProvider(resource=Resource.create({
        ResourceAttributes.SERVICE_NAME: os.getenv("PSONO_OTEL_RESOURCE_SERVICE_NAME", "psono-server"),
        ResourceAttributes.SERVICE_VERSION: os.getenv("PSONO_OTEL_RESOURCE_SERVICE_VERSION", settings.VERSION),
    }))
    trace.set_tracer_provider(trace_provider)
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter())
    )

    RedisInstrumentor().instrument()
    RequestsInstrumentor().instrument()
    DjangoInstrumentor().instrument()

def setup_user_in_baggage_and_spans(user, token):
    if not is_opentelemetry_enabled():
        return

    current_span = get_current_span()

    def set_helper(name, attr, source, set_baggage=False):
        try:
            value = attrgetter(attr)(source)
        except AttributeError:
            value = None
        if not value:
            return

        if isinstance(value, uuid.UUID):
            value = str(value)

        current_span.set_attribute(name, value)
        if set_baggage:
            context.attach(baggage.set_baggage(name, value))

    set_helper("user.id", "id", user, set_baggage=True)
    set_helper("token.id", "id", token, set_baggage=True)
