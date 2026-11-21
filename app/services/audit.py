"""Structured security audit trail.

Events go two places:
* an in-memory ring buffer the dashboard reads (fast, bounded memory), and
* an append-only JSON Lines file you can ship to a SIEM (Splunk, Cortex XSIAM, Elastic).

Raw prompts are never written — only a SHA-256 hash, so an analyst can
correlate repeat attacks without the log itself becoming a PII store.
"""

from __future__ import annotations

import threading
from collections import Counter, deque
from pathlib import Path

from app.schemas import Action, AuditEvent, AuditStats


class AuditLogger:
    def __init__(self, path: str | None, buffer_size: int = 500) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self._path: Path | None = None
        if path:
            self._path = Path(path)
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: AuditEvent) -> None:
        line = event.model_dump_json()
        with self._lock:
            self._events.append(event)
            if self._path:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")

    def recent(self, limit: int = 100, action: Action | None = None) -> list[AuditEvent]:
        with self._lock:
            events = list(self._events)
        events.reverse()  # newest first
        if action:
            events = [e for e in events if e.action == action]
        return events[:limit]

    def stats(self) -> AuditStats:
        with self._lock:
            events = list(self._events)
        rules = Counter(r for e in events for r in e.triggered_rules)
        return AuditStats(
            total_events=len(events),
            by_action=dict(Counter(e.action.value for e in events)),
            by_stage=dict(Counter(e.stage.value for e in events)),
            top_rules=rules.most_common(8),
        )
