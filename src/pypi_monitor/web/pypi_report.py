"""Text of a malware report to PyPI. A person reads and sends it: nothing goes out by itself."""

from urllib.parse import quote

from pypi_monitor.web.queries import ReleaseCard

MAX_SIGNALS = 5
MAX_EVIDENCE = 600


def report_text(card: ReleaseCard) -> str:
    name, version = card.package.normalized_name, card.release.version
    path = f"{quote(name, safe='')}/{quote(version, safe='')}"
    lines = [
        f"Malicious release: {card.package.name} {version}",
        "",
        f"Project: https://pypi.org/project/{path}/",
        f"Inspector: https://inspector.pypi.io/project/{path}/",
    ]
    if card.release.published_at:
        lines.append(f"Uploaded: {card.release.published_at:%Y-%m-%d %H:%M} UTC")
    if card.release.maintainers:
        lines.append(f"Owners: {', '.join(card.release.maintainers)}")
    if card.previous_version:
        lines.append(f"Previous version: {card.previous_version}")
    lines += ["", "Files:"]
    lines += [f"- {a.filename}\n  sha256: {a.sha256}" for a in card.artifacts]
    comment = next((v.comment for v in card.labels if v.comment), None)
    lines += ["", "Why this is malicious:", comment or "<describe what the code does>", ""]
    lines.append("Evidence:")
    for signal in card.signals[:MAX_SIGNALS]:
        lines.append(f"- {signal.rule_id}{f' at {signal.location}' if signal.location else ''}")
        lines += [f"    {line}" for line in signal.evidence[:MAX_EVIDENCE].splitlines()]
    return "\n".join(lines) + "\n"
