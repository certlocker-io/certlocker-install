#!/usr/bin/env python3
"""Translate Alertmanager webhook payloads into Google Chat text messages."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


WEBHOOK_FILE = os.environ.get(
    "GOOGLE_CHAT_WEBHOOK_FILE", "/run/secrets/google_chat_webhook_url"
)
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9094"))
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576
MAX_MESSAGE_CHARS = 30_000
LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100").rstrip("/")
LOKI_TIMEOUT_SECONDS = float(os.environ.get("LOKI_TIMEOUT_SECONDS", "8"))
LOKI_MAX_RESPONSE_BYTES = 8_388_608
JAVA_TRACE_LINE_LIMIT = 100
JAVA_TRACE_CHAR_LIMIT = 24_000
JAVA_ALERT_NAMES = frozenset(("JavaExceptionBurst", "JavaUnhandledException"))
LOKI_JAVA_QUERY_PATTERN = (
    r"(?i)(Exception|Caused by:|stackTrace|suppressStack|CLRT[0-9]+|\s+at\s+)"
)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SERIALIZED_STACK_RE = re.compile(r"stackTrace=\{([^{}]+)\}")
SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|authorization|api[-_]?key)"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^,;\r\n]+)"
)
SECRET_QUERY_RE = re.compile(r"(?i)([?&](?:key|token|api[-_]?key)=)[^&\s]+")


def _webhook_url() -> str:
    with open(WEBHOOK_FILE, encoding="utf-8") as webhook_file:
        return webhook_file.read().strip()


def _alert_line(alert: dict) -> str:
    labels = alert.get("labels") or {}
    annotations = alert.get("annotations") or {}
    name = str(labels.get("alertname") or "UnnamedAlert")
    severity = str(labels.get("severity") or "unknown")
    company = str(labels.get("company") or "unknown-company")
    deployment = str(labels.get("deployment") or "unknown-deployment")
    environment = str(labels.get("environment") or f"uncloud-{company}-{deployment}")
    stack = str(labels.get("stack") or environment or "unknown-stack")
    service = str(labels.get("compose_service") or labels.get("service") or "unknown-service")
    instance = str(labels.get("container") or labels.get("instance") or "unknown-instance")
    summary = str(annotations.get("summary") or annotations.get("description") or "")
    suffix = f" — {summary}" if summary else ""
    return (
        f"• [{severity.upper()}] {name}"
        f" — Source: company={company}, deployment={deployment}, environment={environment}, "
        f"stack={stack}, service={service}, instance={instance}"
        f"{suffix}"
    )


def _parse_alert_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value or value.startswith("0001-"):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _loki_selector(labels: dict) -> str | None:
    selector = []
    for label_name in ("stack", "compose_service", "container"):
        label_value = labels.get(label_name)
        if label_value:
            # JSON string quoting is also valid for LogQL label values.
            selector.append(f"{label_name}={json.dumps(str(label_value))}")
    if not selector or not labels.get("compose_service"):
        return None
    return "{" + ",".join(selector) + "}"


def _query_loki_java_logs(alert: dict) -> list[str]:
    labels = alert.get("labels") or {}
    selector = _loki_selector(labels)
    if not selector or not LOKI_URL:
        return []

    now = datetime.now(timezone.utc)
    alert_start = _parse_alert_time(alert.get("startsAt")) or now
    alert_end = _parse_alert_time(alert.get("endsAt"))
    query_start = alert_start - timedelta(minutes=12)
    # The ruler looks back ten minutes. Query that lead-in plus the beginning of
    # the incident, rather than an unbounded range for long-running alerts.
    query_end = min(alert_start + timedelta(minutes=20), alert_end or now)
    if query_end <= query_start:
        query_end = alert_start + timedelta(minutes=2)

    query = f"{selector} |~ {json.dumps(LOKI_JAVA_QUERY_PATTERN)}"
    parameters = urlencode(
        {
            "query": query,
            "start": int(query_start.timestamp() * 1_000_000_000),
            "end": int(query_end.timestamp() * 1_000_000_000),
            "limit": 1000,
            "direction": "forward",
        }
    )
    request = Request(
        f"{LOKI_URL}/loki/api/v1/query_range?{parameters}",
        headers={"Accept": "application/json"},
    )
    with urlopen(request, timeout=LOKI_TIMEOUT_SECONDS) as response:
        raw_response = response.read(LOKI_MAX_RESPONSE_BYTES + 1)
    if len(raw_response) > LOKI_MAX_RESPONSE_BYTES:
        raise ValueError("Loki response exceeded safety limit")
    payload = json.loads(raw_response)
    entries: list[tuple[int, str]] = []
    for stream in (payload.get("data") or {}).get("result") or []:
        for value in stream.get("values") or []:
            if len(value) != 2:
                continue
            try:
                timestamp = int(value[0])
            except (TypeError, ValueError):
                continue
            entries.append((timestamp, str(value[1])))
    entries.sort(key=lambda entry: entry[0])
    return [line for _, line in entries]


def _redact_trace_line(line: str) -> str:
    line = ANSI_ESCAPE_RE.sub("", line).replace("```", "''' ")
    line = SECRET_PAIR_RE.sub(r"\1\2[REDACTED]", line)
    return SECRET_QUERY_RE.sub(r"\1[REDACTED]", line)


def _exception_header(line: str) -> str:
    clean = _redact_trace_line(line).strip()
    message = re.search(r"(?:detailMessage|message)=([^,\r\n]+)", clean)
    if message:
        return message.group(1).strip()
    stack_marker = clean.find("stackTrace={")
    if stack_marker >= 0:
        clean = clean[:stack_marker].rstrip(" ,")
    return clean[:1200]


def _serialized_trace(line: str) -> list[str]:
    best_frames: list[str] = []
    for match in SERIALIZED_STACK_RE.finditer(line):
        frames = []
        for raw_frame in match.group(1).split(","):
            frame = _redact_trace_line(raw_frame).strip()
            if "(" not in frame or ")" not in frame or "." not in frame:
                continue
            frames.append(frame if frame.startswith("at ") else f"at {frame}")
        if len(frames) > len(best_frames):
            best_frames = frames
    if not best_frames:
        return []
    header = _exception_header(line)
    return ([header] if header else []) + best_frames


def _format_java_trace(log_lines: list[str]) -> tuple[str, int]:
    # CertLocker sometimes serializes an entire Throwable into one Docker log
    # record. Prefer the record containing the most frames so repeated exception
    # summaries do not consume the 100-line allowance.
    best_trace: list[str] = []
    for log_line in log_lines:
        candidate = _serialized_trace(log_line)
        if len(candidate) > len(best_trace):
            best_trace = candidate

    if not best_trace:
        seen = set()
        for log_line in log_lines:
            for raw_line in log_line.splitlines():
                line = _redact_trace_line(raw_line).strip()
                if not line or line in seen:
                    continue
                seen.add(line)
                best_trace.append(line[:2000])
                if len(best_trace) >= JAVA_TRACE_LINE_LIMIT:
                    break
            if len(best_trace) >= JAVA_TRACE_LINE_LIMIT:
                break

    selected = best_trace[:JAVA_TRACE_LINE_LIMIT]
    while selected and len("\n".join(selected)) > JAVA_TRACE_CHAR_LIMIT:
        selected.pop()
    if not selected and best_trace:
        selected = [best_trace[0][:JAVA_TRACE_CHAR_LIMIT]]
    return "\n".join(selected), len(selected)


def _alert_text(alert: dict) -> str:
    text = _alert_line(alert)
    labels = alert.get("labels") or {}
    if labels.get("alertname") not in JAVA_ALERT_NAMES:
        return text
    try:
        trace, line_count = _format_java_trace(_query_loki_java_logs(alert))
    except (OSError, HTTPError, URLError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(
            "google-chat-alerts: Loki trace lookup failed: "
            + type(exc).__name__
            + "\n"
        )
        trace, line_count = "", 0
    if trace:
        text += (
            f"\nJava stack trace ({line_count} line"
            f"{'s' if line_count != 1 else ''}, maximum {JAVA_TRACE_LINE_LIMIT}):"
            f"\n```\n{trace}\n```"
        )
    else:
        text += "\nJava stack trace unavailable from Loki for the incident window."
    return text


def _chat_text(payload: dict) -> str:
    status = str(payload.get("status", "firing")).upper()
    alerts = payload.get("alerts") or []
    receiver = str(payload.get("receiver") or "certlocker-alerts")
    environments = sorted(
        {
            str(
                (alert.get("labels") or {}).get("environment")
                or (alert.get("labels") or {}).get("stack")
                or (
                    f"uncloud-{(alert.get('labels') or {}).get('company')}-"
                    f"{(alert.get('labels') or {}).get('deployment')}"
                    if (alert.get("labels") or {}).get("company")
                    else ""
                )
            )
            for alert in alerts
        }
    )
    environments = [item for item in environments if item]
    lines = [
        f"CertLocker alerts — {status}",
        f"Environment(s): {', '.join(environments) if environments else 'unknown-environment'}",
        f"Receiver: {receiver}",
    ]
    lines.extend(_alert_text(alert) for alert in alerts)
    if not alerts:
        lines.append("• Alertmanager sent an empty alert group")
    text = "\n".join(lines)
    if len(text) > MAX_MESSAGE_CHARS:
        text = text[: MAX_MESSAGE_CHARS - 40]
        if text.count("```") % 2:
            text += "\n```"
        text += "\n… message truncated"
    return text


def _deliver_chat_text(text: str) -> dict:
    """Post one text message and require Google Chat to echo parsed content."""
    body = json.dumps({"text": text}).encode("utf-8")
    request = Request(
        _webhook_url(),
        data=body,
        headers={"Content-Type": "application/json; charset=UTF-8"},
        method="POST",
    )
    with urlopen(request, timeout=15) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"Google Chat returned HTTP {response.status}")
        raw_response = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw_response) > MAX_RESPONSE_BYTES:
        raise RuntimeError("Google Chat response exceeded safety limit")
    try:
        message = json.loads(raw_response)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("Google Chat returned a non-JSON response") from exc
    if not isinstance(message, dict):
        raise RuntimeError("Google Chat returned a non-object response")
    if message.get("text") != text or not str(message.get("name") or "").strip():
        raise RuntimeError("Google Chat did not echo the parsed text message")
    return message


class Handler(BaseHTTPRequestHandler):
    server_version = "certlocker-google-chat-alerts/1"

    def log_message(self, message_format: str, *args: object) -> None:
        sys.stderr.write("google-chat-alerts: " + (message_format % args) + "\n")

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_error(404)
            return
        try:
            configured = bool(_webhook_url())
        except OSError:
            configured = False
        self.send_response(200 if configured else 503)
        self.end_headers()
        self.wfile.write(b"ok\n" if configured else b"webhook not configured\n")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/alerts":
            self.send_error(404)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
                raise ValueError("invalid request size")
            payload = json.loads(self.rfile.read(content_length))
            _deliver_chat_text(_chat_text(payload))
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_error(400, str(exc))
            return
        except (OSError, HTTPError, URLError, RuntimeError) as exc:
            self.log_error("delivery failed: %s", type(exc).__name__)
            self.send_error(502, "Google Chat delivery failed")
            return
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()
