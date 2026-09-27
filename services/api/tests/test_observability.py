import json
import logging

from opentelemetry.sdk.trace import TracerProvider

from app.observability import JsonFormatter


def _record(**extra: object) -> logging.LogRecord:
    record = logging.LogRecord("warden.test", logging.INFO, __file__, 1, "hello %s", ("x",), None)
    record.__dict__.update(extra)
    return record


def test_formats_json_with_pipeline_context() -> None:
    out = json.loads(JsonFormatter().format(_record(scan_id="s1", host_id="h1", stage="discover")))

    assert out["msg"] == "hello x"
    assert out["level"] == "info"
    assert (out["scan_id"], out["host_id"], out["stage"]) == ("s1", "h1", "discover")
    assert "trace_id" not in out


def test_includes_trace_ids_inside_span() -> None:
    tracer = TracerProvider().get_tracer(__name__)

    with tracer.start_as_current_span("op") as span:
        out = json.loads(JsonFormatter().format(_record()))

    ctx = span.get_span_context()
    assert out["trace_id"] == format(ctx.trace_id, "032x")
    assert out["span_id"] == format(ctx.span_id, "016x")
