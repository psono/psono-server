from django.apps import AppConfig
import os

class RestapiConfig(AppConfig):
    name = "restapi"

    def ready(self):
        """Set up OTLP"""
        if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", ""):
            from restapi.telemetry import setup_telemetry
            setup_telemetry()
