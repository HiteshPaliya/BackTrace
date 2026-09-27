"""Thread-safe durable append-only event log (.audit/events.jsonl)."""

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

CRITICAL_EVENT_TYPES = {
    "PATH_TRANSITION",
    "DOSSIER_SYNTHESIZED",
    "CIRCUIT_BREAKER_TRIGGERED",
}


@dataclass
class EventRecord:
    """Canonical event structure logged to .audit/events.jsonl."""

    event_id: str
    timestamp: str
    scan_id: str
    component: str
    event_type: str
    payload: Dict[str, Any]


class EventLogger:
    """Thread-safe, durable append-only event stream logger with immediate flush."""

    def __init__(self, log_path: Path | str, scan_id: str) -> None:
        self.log_path = Path(log_path).resolve()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.scan_id = scan_id
        self._lock = threading.Lock()

    def log(
        self,
        component: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Atomically log an event line to JSON Lines and flush critical transitions."""
        record = EventRecord(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            scan_id=self.scan_id,
            component=component,
            event_type=event_type,
            payload=payload,
        )

        record_dict = asdict(record)
        json_line = json.dumps(record_dict, default=str) + "\n"

        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json_line)
                f.flush()
                if event_type in CRITICAL_EVENT_TYPES:
                    sync_fn = getattr(os, "fdatasync", os.fsync)
                    sync_fn(f.fileno())

        return record_dict
