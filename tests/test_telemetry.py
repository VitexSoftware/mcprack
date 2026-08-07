import logging

import pytest

from mcprack import telemetry
from mcprack.app import create_app
from mcprack.config import Config


try:
    import opentelemetry.sdk  # noqa: F401
    HAS_OTEL_SDK = True
except ImportError:
    HAS_OTEL_SDK = False


class OtelDisabledConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    OTEL_ENABLED = False


class OtelEnabledConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret"
    OTEL_ENABLED = True
    OTEL_EXPORTER_OTLP_ENDPOINT = "http://otel-collector.invalid:4318"
    OTEL_EXPORTER_OTLP_PROTOCOL = "http/protobuf"


def _make_fake_exporters():
    from opentelemetry.sdk.metrics.export import MetricExportResult, MetricExporter
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    class FakeSpanExporter(SpanExporter):
        def __init__(self):
            self.exported_spans = []

        def export(self, spans):
            self.exported_spans.extend(spans)
            return SpanExportResult.SUCCESS

        def shutdown(self):
            pass

        def force_flush(self, timeout_millis=30000):
            return True

    class FakeMetricExporter(MetricExporter):
        def __init__(self):
            super().__init__()
            self.exported_batches = []

        def export(self, metrics_data, timeout_millis=10000, **kwargs):
            self.exported_batches.append(metrics_data)
            return MetricExportResult.SUCCESS

        def shutdown(self, timeout_millis=30000, **kwargs):
            return True

        def force_flush(self, timeout_millis=10000):
            return True

    return FakeSpanExporter(), FakeMetricExporter()


@pytest.fixture(autouse=True)
def _reset_telemetry_state():
    """telemetry._state is module-global — make sure one test's
    init_app() call never leaks into the next."""
    yield
    telemetry._state["enabled"] = False


def test_disabled_is_a_true_noop(monkeypatch):
    app = create_app(OtelDisabledConfig)
    assert telemetry.is_enabled() is False

    # No exporter classes should even be touched.
    called = []
    monkeypatch.setattr(telemetry, "_build_span_exporter", lambda *a: called.append(a) or None)
    monkeypatch.setattr(telemetry, "_build_metric_exporter", lambda *a: called.append(a) or None)
    telemetry.init_app(app)
    assert called == []

    with telemetry.span("does.not.matter", {"x": 1}) as s:
        assert s is None

    # Recording metrics must never raise even though no instruments exist.
    telemetry.record_mcp_server_call("srv", "stdio", "success", 0.01)
    telemetry.record_config_download("claude")


@pytest.mark.skipif(not HAS_OTEL_SDK, reason="opentelemetry-sdk not installed")
def test_enabled_sends_spans_and_metrics(monkeypatch):
    fake_span_exporter, fake_metric_exporter = _make_fake_exporters()
    monkeypatch.setattr(telemetry, "_build_span_exporter", lambda *a: fake_span_exporter)
    monkeypatch.setattr(telemetry, "_build_metric_exporter", lambda *a: fake_metric_exporter)

    app = create_app(OtelEnabledConfig)
    assert telemetry.is_enabled() is True

    with telemetry.span("mcp.server.call", {"server_name": "jenkins", "transport": "stdio"}):
        pass
    telemetry.record_mcp_server_call("jenkins", "stdio", "success", 0.25)

    telemetry._state["tracer_provider"].force_flush(timeout_millis=5000)
    telemetry._state["meter_provider"].force_flush(timeout_millis=5000)

    # Filter for our own span by name rather than asserting an exact total:
    # if this happens to be the first OTEL-enabled test in the process,
    # SQLAlchemyInstrumentor's one-shot global instrument() call (see
    # telemetry.py's _instrument_sqlalchemy) also captures the schema-
    # bootstrap queries create_app() issues right after telemetry.init_app(),
    # adding incidental spans that have nothing to do with what this test
    # actually exercises.
    mcp_spans = [s for s in fake_span_exporter.exported_spans if s.name == "mcp.server.call"]
    assert len(mcp_spans) == 1
    assert mcp_spans[0].attributes["server_name"] == "jenkins"
    assert len(fake_metric_exporter.exported_batches) >= 1


@pytest.mark.skipif(not HAS_OTEL_SDK, reason="opentelemetry-sdk not installed")
def test_http_json_protocol_falls_back_with_warning(monkeypatch, caplog):
    fake_span_exporter, fake_metric_exporter = _make_fake_exporters()
    monkeypatch.setattr(telemetry, "_build_span_exporter", lambda *a: fake_span_exporter)
    monkeypatch.setattr(telemetry, "_build_metric_exporter", lambda *a: fake_metric_exporter)

    class OtelJsonConfig(OtelEnabledConfig):
        OTEL_EXPORTER_OTLP_PROTOCOL = "http/json"

    with caplog.at_level(logging.WARNING, logger="mcprack.telemetry"):
        create_app(OtelJsonConfig)

    assert telemetry.status()["effective_protocol"] == "http/protobuf"
    assert telemetry.status()["protocol_fell_back"] is True
    assert any("http/json" in rec.message and "not supported" in rec.message for rec in caplog.records)


@pytest.mark.skipif(not HAS_OTEL_SDK, reason="opentelemetry-sdk not installed")
def test_resolve_protocol_selects_correct_exporter_class(monkeypatch):
    """Verifies the *class* picked for http/json falls back to the
    http/protobuf exporter class, never the grpc one and never a
    'http/json' exporter (which does not exist)."""
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter as GrpcSpanExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter as HttpSpanExporter,
    )

    effective, fell_back = telemetry.resolve_protocol("http/json")
    assert effective == "http/protobuf"
    assert fell_back is True

    exporter = telemetry._build_span_exporter(effective, "http://otel-collector.invalid:4318")
    assert isinstance(exporter, HttpSpanExporter)
    assert not isinstance(exporter, GrpcSpanExporter)


@pytest.mark.skipif(not HAS_OTEL_SDK, reason="opentelemetry-sdk not installed")
def test_grpc_protocol_uses_grpc_exporter_class():
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter as GrpcSpanExporter,
    )

    effective, fell_back = telemetry.resolve_protocol("grpc")
    assert effective == "grpc"
    assert fell_back is False

    exporter = telemetry._build_span_exporter(effective, "http://otel-collector.invalid:4317")
    assert isinstance(exporter, GrpcSpanExporter)


@pytest.mark.skipif(not HAS_OTEL_SDK, reason="opentelemetry-sdk not installed")
def test_request_id_appears_as_span_attribute(monkeypatch):
    fake_span_exporter, fake_metric_exporter = _make_fake_exporters()
    monkeypatch.setattr(telemetry, "_build_span_exporter", lambda *a: fake_span_exporter)
    monkeypatch.setattr(telemetry, "_build_metric_exporter", lambda *a: fake_metric_exporter)

    app = create_app(OtelEnabledConfig)

    from mcprack import audit

    with app.test_request_context("/"):
        request_id = audit.current_request_id()
        with telemetry.span("catalog.generate_config", {"client_type": "claude"}):
            pass

    telemetry._state["tracer_provider"].force_flush(timeout_millis=5000)

    # See test_enabled_sends_spans_and_metrics for why this filters by name
    # rather than asserting an exact total.
    catalog_spans = [
        s for s in fake_span_exporter.exported_spans if s.name == "catalog.generate_config"
    ]
    assert len(catalog_spans) == 1
    recorded = catalog_spans[0]
    assert recorded.attributes["audit.request_id"] == request_id


def test_send_test_signal_reports_disabled_when_off():
    app = create_app(OtelDisabledConfig)
    ok, detail = telemetry.send_test_signal()
    assert ok is False
    assert "not enabled" in detail


@pytest.mark.skipif(not HAS_OTEL_SDK, reason="opentelemetry-sdk not installed")
def test_send_test_signal_ok_when_enabled(monkeypatch):
    fake_span_exporter, fake_metric_exporter = _make_fake_exporters()
    monkeypatch.setattr(telemetry, "_build_span_exporter", lambda *a: fake_span_exporter)
    monkeypatch.setattr(telemetry, "_build_metric_exporter", lambda *a: fake_metric_exporter)

    create_app(OtelEnabledConfig)
    ok, detail = telemetry.send_test_signal()
    assert ok is True
    assert len(fake_span_exporter.exported_spans) == 1
