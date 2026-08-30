"""OpenTelemetry wiring for mcprack — traces + metrics over OTLP.

Deliberately a no-op when OTEL_ENABLED is false/unset: init_app() returns
immediately, every span() context manager becomes a null context, and every
metric recorder becomes a no-op function. None of the opentelemetry-*
packages need to even be installed unless OTEL_ENABLED=true — see
requirements-otel.txt and README "Observability (OpenTelemetry)".

Protocol handling: the Python OTLP exporter ships two transports only,
"grpc" and "http/protobuf" — unlike the JS SDK there is no "http/json"
exporter at all. If OTEL_EXPORTER_OTLP_PROTOCOL is "http/json" (or anything
else unrecognized), we log a warning at startup and fall back to
http/protobuf; we never fail application startup over a bad OTEL setting.

Every custom span/metric here carries only identifiers and outcomes
(server names, hashed secret names, durations, success/error) — never
request/response bodies or credential values, mirroring the same rule
audit.py follows.
"""

import contextlib
import hashlib
import logging
import socket

logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOLS = ("grpc", "http/protobuf")
DEFAULT_PROTOCOL = "http/protobuf"

_state = {
    "enabled": False,
    "tracer": None,
    "meter": None,
    "requested_protocol": None,
    "effective_protocol": None,
    "protocol_fell_back": False,
    "endpoint": None,
    "service_name": None,
    "tracer_provider": None,
    "meter_provider": None,
    "instruments": {},
    "init_error": None,
}


def resolve_protocol(requested):
    """Returns (effective_protocol, fell_back). Never raises."""
    if not requested or not requested.strip():
        return DEFAULT_PROTOCOL, False
    normalized = requested.strip().lower()
    if normalized == "http/json":
        return DEFAULT_PROTOCOL, True
    if normalized in SUPPORTED_PROTOCOLS:
        return normalized, False
    return DEFAULT_PROTOCOL, True


def hash_secret_name(name):
    """One-way identifier for a secret/item name, safe to put in a span
    attribute — never the secret value itself, and not even the plain name
    (which can itself be sensitive, e.g. embeds a username)."""
    if not name:
        return None
    return hashlib.sha256(name.encode()).hexdigest()[:16]


def is_enabled():
    return bool(_state["enabled"])


def status():
    """Snapshot for the admin OTEL diagnostics page."""
    return dict(_state)


def init_app(app):
    """Call once from the app factory. Reads OTEL_* from app.config."""
    global _state
    enabled = bool(app.config.get("OTEL_ENABLED", False))
    _state = {
        "enabled": False,
        "tracer": None,
        "meter": None,
        "requested_protocol": app.config.get("OTEL_EXPORTER_OTLP_PROTOCOL"),
        "effective_protocol": None,
        "protocol_fell_back": False,
        "endpoint": app.config.get("OTEL_EXPORTER_OTLP_ENDPOINT") or None,
        "service_name": app.config.get("OTEL_SERVICE_NAME", "mcprack"),
        "traces_sampler": app.config.get("OTEL_TRACES_SAMPLER"),
        "tracer_provider": None,
        "meter_provider": None,
        "instruments": {},
        "init_error": None,
    }

    if not enabled:
        logger.info("OpenTelemetry disabled (OTEL_ENABLED is not set/true)")
        return

    effective_protocol, fell_back = resolve_protocol(_state["requested_protocol"])
    _state["effective_protocol"] = effective_protocol
    _state["protocol_fell_back"] = fell_back
    if fell_back:
        requested = _state["requested_protocol"]
        if requested and requested.strip().lower() == "http/json":
            logger.warning(
                "OTEL_EXPORTER_OTLP_PROTOCOL=http/json is not supported by the Python "
                "OTLP exporter; falling back to http/protobuf"
            )
        else:
            logger.warning(
                "Unknown OTEL_EXPORTER_OTLP_PROTOCOL=%r; falling back to http/protobuf",
                requested,
            )

    try:
        _init_sdk(app, effective_protocol)
    except (ImportError, ModuleNotFoundError) as exc:
        # By far the most common init failure: OTEL_ENABLED=true was set but
        # the optional opentelemetry-* packages were never installed (they
        # are deliberately NOT a hard dependency of mcprack — see the
        # module docstring). Make the fix obvious in the admin OTEL
        # diagnostics page instead of surfacing a bare "No module named ...".
        logger.exception(
            "OpenTelemetry packages are not installed — continuing without OTEL. "
            "Install them with `pip install -r requirements-otel.txt` or the "
            "python3-opentelemetry-* Debian packages listed in debian/control's "
            "Suggests, then restart mcprack."
        )
        _state["enabled"] = False
        _state["init_error"] = (
            f"{exc} — the opentelemetry-* dependencies are not installed. Install them "
            "with `pip install -r requirements-otel.txt` (or the python3-opentelemetry-* "
            "Debian packages listed in debian/control's Suggests), then restart mcprack."
        )
    except Exception as exc:  # pragma: no cover - defensive, see docstring
        logger.exception("Failed to initialize OpenTelemetry — continuing without it")
        _state["enabled"] = False
        _state["init_error"] = str(exc)


def _build_span_exporter(protocol, endpoint):
    if protocol == "grpc":
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )

        return OTLPSpanExporter(endpoint=endpoint) if endpoint else OTLPSpanExporter()

    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )

    if endpoint:
        return OTLPSpanExporter(endpoint=_with_signal_path(endpoint, "traces"))
    return OTLPSpanExporter()


def _build_metric_exporter(protocol, endpoint):
    if protocol == "grpc":
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
            OTLPMetricExporter,
        )

        return OTLPMetricExporter(endpoint=endpoint) if endpoint else OTLPMetricExporter()

    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )

    if endpoint:
        return OTLPMetricExporter(endpoint=_with_signal_path(endpoint, "metrics"))
    return OTLPMetricExporter()


def _with_signal_path(endpoint, signal):
    """http/protobuf exporters take the endpoint verbatim when given one
    explicitly (only the *env var* auto-config path appends /v1/<signal>) —
    so we replicate that append ourselves for a base endpoint like
    'http://host:4318'. An endpoint that already ends in the right path is
    left alone."""
    base = endpoint.rstrip("/")
    if base.endswith(f"/v1/{signal}"):
        return base
    return f"{base}/v1/{signal}"


def _init_sdk(app, effective_protocol):
    from opentelemetry import metrics, trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    endpoint = _state["endpoint"]
    service_name = _state["service_name"]
    resource = Resource.create({"service.name": service_name})

    span_exporter = _build_span_exporter(effective_protocol, endpoint)
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))

    metric_exporter = _build_metric_exporter(effective_protocol, endpoint)
    metric_reader = PeriodicExportingMetricReader(metric_exporter)
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])

    # Deliberately get tracer/meter from *our own* provider objects, not the
    # global trace.get_tracer()/metrics.get_meter() proxies: the global
    # TracerProvider/MeterProvider can only be set once per process
    # (subsequent set_tracer_provider calls are silently ignored), which
    # would otherwise make a second create_app() call in the same process
    # (e.g. across tests) silently keep using the first one's exporter.
    tracer = tracer_provider.get_tracer("mcprack")
    meter = meter_provider.get_meter("mcprack")

    # Still register globally on a best-effort basis, for any third-party
    # code that only knows how to look the provider up via the global API —
    # our own instrumentation below always gets an explicit tracer_provider/
    # meter_provider instead of relying on this.
    try:
        trace.set_tracer_provider(tracer_provider)
        metrics.set_meter_provider(meter_provider)
    except Exception:  # pragma: no cover - defensive
        pass

    _state.update(
        {
            "enabled": True,
            "tracer": tracer,
            "meter": meter,
            "tracer_provider": tracer_provider,
            "meter_provider": meter_provider,
        }
    )

    _init_instruments(meter)
    _instrument_flask(app, tracer_provider, meter_provider)
    _instrument_sqlalchemy(app, tracer_provider)


def _init_instruments(meter):
    instruments = {
        "mcp_server_calls_total": meter.create_counter(
            "mcp_server_calls_total", description="MCP server calls, by server and result"
        ),
        "mcp_server_call_duration_seconds": meter.create_histogram(
            "mcp_server_call_duration_seconds",
            unit="s",
            description="MCP server call duration",
        ),
        "config_downloads_total": meter.create_counter(
            "config_downloads_total", description="Client config downloads, by client type"
        ),
    }
    _state["instruments"] = instruments


def _instrument_flask(app, tracer_provider, meter_provider):
    from opentelemetry.instrumentation.flask import FlaskInstrumentor

    # instrument_app() is idempotent per Flask app instance (it stamps
    # app._is_instrumented_by_opentelemetry itself) — safe to call
    # unconditionally here.
    FlaskInstrumentor().instrument_app(
        app, tracer_provider=tracer_provider, meter_provider=meter_provider
    )


def _instrument_sqlalchemy(app, tracer_provider):
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

    from .extensions import db

    # Unlike FlaskInstrumentor, SQLAlchemyInstrumentor's instrument() is a
    # process-global one-shot (a second call just warns and no-ops) — fine
    # for a real single-process deployment; in tests it means only the
    # first app's engine in a process actually gets query spans.
    with app.app_context():
        SQLAlchemyInstrumentor().instrument(engine=db.engine, tracer_provider=tracer_provider)


# --- Public span/metric API — safe to call unconditionally -----------------


@contextlib.contextmanager
def span(name, attributes=None):
    """Start a span if OTEL is enabled; a harmless null context otherwise.
    Also tags the span with audit.request_id when a request is in flight,
    so a trace can be found starting from an audit log entry."""
    if not _state["enabled"] or _state["tracer"] is None:
        yield None
        return

    from . import audit

    with _state["tracer"].start_as_current_span(name) as current_span:
        if attributes:
            for key, value in attributes.items():
                if value is not None:
                    current_span.set_attribute(key, value)
        request_id = audit.current_request_id()
        if request_id:
            current_span.set_attribute("audit.request_id", request_id)
        yield current_span


def record_mcp_server_call(server_name, transport, result, duration_seconds, extra_attributes=None):
    """extra_attributes is for callers (currently just send_test_signal below)
    that need extra dimensions beyond server_name/result on this one call,
    without changing the label set every real MCP proxy call produces."""
    instruments = _state.get("instruments") or {}
    counter = instruments.get("mcp_server_calls_total")
    histogram = instruments.get("mcp_server_call_duration_seconds")
    counter_attrs = {"server_name": server_name or "unknown", "result": result}
    histogram_attrs = {"server_name": server_name or "unknown"}
    if extra_attributes:
        counter_attrs.update(extra_attributes)
        histogram_attrs.update(extra_attributes)
    if counter is not None:
        counter.add(1, counter_attrs)
    if histogram is not None:
        histogram.record(duration_seconds, histogram_attrs)


def record_config_download(client_type):
    instruments = _state.get("instruments") or {}
    counter = instruments.get("config_downloads_total")
    if counter is not None:
        counter.add(1, {"client_type": client_type or "unknown"})


def send_test_signal():
    """Used by the OTEL diagnostics page: emit one span and one metric
    point and force-flush them, so a real export attempt happens
    synchronously and any exception surfaces immediately instead of being
    swallowed by the background export thread. Returns (ok, detail).

    Every mcprack instance sharing a Collector fires this from the same
    admin page, so the resulting series/span must be self-identifying on
    its own — never rely solely on the OTLP resource attributes
    (service.name/host.name) a downstream Collector attaches, since a
    misconfigured Collector can silently drop them (e.g. a `prometheus`
    exporter without `resource_to_telemetry_conversion` enabled turns
    service.name into only the `job`/`instance` target_info labels, never a
    per-series label) or overwrite host.name with its own hostname (the
    OTLP receiver's `resourcedetection` processor detects the Collector
    host, not the origin). We therefore bake the origin hostname directly
    into the server_name value itself — and repeat it as an explicit
    `mcprack.diagnostics.hostname` attribute for programmatic filtering —
    so the signal is traceable to its source purely from its own
    attributes, with no dependency on Collector-side config."""
    if not _state["enabled"]:
        return False, "OpenTelemetry is not enabled (OTEL_ENABLED is not set/true)."

    hostname = socket.gethostname()
    service_name = _state.get("service_name") or "mcprack"
    diagnostic_server_name = f"otel-diagnostics@{hostname}"

    try:
        with _state["tracer"].start_as_current_span("otel.diagnostics.test_span") as test_span:
            test_span.set_attribute("mcprack.diagnostics", True)
            test_span.set_attribute("mcprack.diagnostics.hostname", hostname)
            test_span.set_attribute("mcprack.diagnostics.service_name", service_name)
        record_mcp_server_call(
            diagnostic_server_name,
            "test",
            "success",
            0.0,
            extra_attributes={
                "mcprack.diagnostics.hostname": hostname,
                "mcprack.diagnostics.service_name": service_name,
            },
        )

        tracer_provider = _state.get("tracer_provider")
        meter_provider = _state.get("meter_provider")
        if tracer_provider is not None:
            tracer_provider.force_flush(timeout_millis=5000)
        if meter_provider is not None:
            meter_provider.force_flush(timeout_millis=5000)
    except Exception as exc:
        return False, f"Test span/metric export failed: {exc}"

    return True, (
        "Test span and metric flushed to the configured OTLP endpoint without error — "
        f"look for server_name='{diagnostic_server_name}' (service_name='{service_name}') "
        "in your metrics/trace backend to confirm it arrived and to tell this instance's "
        "signal apart from any other mcprack host sharing the same Collector."
    )
