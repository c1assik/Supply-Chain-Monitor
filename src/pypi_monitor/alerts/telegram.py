"""Alert delivery. Everything taken from a package is untrusted and escaped."""

import html
import logging
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote

import httpx

from pypi_monitor.analyzers.base import Signal
from pypi_monitor.domain import Severity

log = logging.getLogger(__name__)

API_URL = "https://api.telegram.org"
MAX_SNIPPET_LENGTH = 300


class TelegramError(Exception):
    pass


@dataclass(frozen=True)
class Alert:
    package: str
    version: str
    score: int
    level: Severity
    signals: list[Signal]


class Notifier(Protocol):
    async def send(self, alert: Alert) -> None: ...


def format_alert(alert: Alert) -> str:
    package, version = quote(alert.package, safe=""), quote(alert.version, safe="")
    lines = [
        f"<b>{alert.level.value.upper()} {alert.score}/100</b>",
        f"<code>{html.escape(alert.package)} {html.escape(alert.version)}</code>",
        f'<a href="https://pypi.org/project/{package}/{version}/">PyPI</a> · '
        f'<a href="https://inspector.pypi.io/project/{package}/{version}/">Inspector</a>',
    ]
    for signal in alert.signals:
        location = signal.file_path or ""
        if location and signal.line:
            location = f"{location}:{signal.line}"
        evidence = signal.evidence
        if len(evidence) > MAX_SNIPPET_LENGTH:
            evidence = f"{evidence[:MAX_SNIPPET_LENGTH]}…"
        lines.append(
            f"\n<b>{html.escape(signal.rule_id)}</b> {html.escape(location)}"
            f"\n<pre>{html.escape(evidence)}</pre>"
        )
    return "\n".join(lines)


class TelegramNotifier:
    def __init__(
        self, token: str, chat_id: str, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self._http = httpx.AsyncClient(
            base_url=f"{API_URL}/bot{token}", timeout=30, transport=transport
        )
        self._chat_id = chat_id

    async def aclose(self) -> None:
        await self._http.aclose()

    async def send(self, alert: Alert) -> None:
        response = await self._http.post(
            "/sendMessage",
            json={
                "chat_id": self._chat_id,
                "text": format_alert(alert),
                "parse_mode": "HTML",
                # A preview would make Telegram fetch URLs picked from malicious code.
                "link_preview_options": {"is_disabled": True},
            },
        )
        # Not raise_for_status(): its message has the URL, and the URL has the bot token.
        if response.is_error:
            raise TelegramError(f"Telegram answered {response.status_code}")


class LogNotifier:
    """Used when Telegram is not configured, so that a local run stays observable."""

    async def send(self, alert: Alert) -> None:
        log.warning("ALERT (Telegram is not configured)\n%s", format_alert(alert))
