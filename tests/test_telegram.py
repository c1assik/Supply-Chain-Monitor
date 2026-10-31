import json

import httpx
import pytest

from pypi_monitor.alerts.telegram import Alert, TelegramError, TelegramNotifier, format_alert
from pypi_monitor.analyzers import Signal
from pypi_monitor.domain import Severity


def alert(evidence: str = "exec(base64.b64decode(data))") -> Alert:
    signal = Signal(
        rule_id="guarddog.threat-x",
        severity=Severity.HIGH,
        confidence=1,
        evidence=evidence,
        file_path="pkg/setup.py",
        line=7,
    )
    return Alert("evil-pkg", "1.0", 91, Severity.CRITICAL, [signal])


def test_alert_has_package_score_links_and_evidence() -> None:
    text = format_alert(alert())

    assert "CRITICAL 91/100" in text
    assert "evil-pkg 1.0" in text
    assert "https://pypi.org/project/evil-pkg/1.0/" in text
    assert "guarddog.threat-x" in text
    assert "pkg/setup.py:7" in text
    assert "exec(base64.b64decode(data))" in text


def test_untrusted_text_is_escaped() -> None:
    text = format_alert(alert("</pre><a href='http://evil'>click</a>"))

    assert "<a href='http://evil'>" not in text
    assert "&lt;/pre&gt;" in text


def test_longest_alert_fits_telegram_limit() -> None:
    signals = alert("<" * 100_000).signals * 3

    text = format_alert(Alert("p" * 255, "1", 100, Severity.CRITICAL, signals))

    assert len(text.replace("&lt;", "<")) < 4096


async def test_notifier_disables_previews_and_raises_on_failure() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200 if len(requests) == 1 else 429, json={})

    notifier = TelegramNotifier("TOKEN", "42", httpx.MockTransport(handler))

    await notifier.send(alert())
    with pytest.raises(TelegramError) as error:
        await notifier.send(alert())
    await notifier.aclose()

    assert "TOKEN" not in str(error.value)
    body = json.loads(requests[0].content)
    assert requests[0].url.path == "/botTOKEN/sendMessage"
    assert body["chat_id"] == "42"
    assert body["link_preview_options"] == {"is_disabled": True}
