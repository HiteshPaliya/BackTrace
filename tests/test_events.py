"""Tests for EventLogger and durable event stream."""

import json
import threading
from pathlib import Path
from unittest.mock import patch

from src.storage.events import CRITICAL_EVENT_TYPES, EventLogger


def test_event_logger_concurrent_thread_safety(tmp_path: Path):
    """Happy path: Dispatch concurrent writes from multiple threads without corruption."""
    log_file = tmp_path / ".audit" / "events.jsonl"
    logger = EventLogger(log_file, scan_id="test-scan-123")

    def log_worker(worker_id):
        for i in range(25):
            logger.log("STRANDS_AGENT", "AGENT_STEP", {"worker": worker_id, "step": i})

    threads = [threading.Thread(target=log_worker, args=(t,)) for t in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 100
    for line in lines:
        record = json.loads(line)
        assert record["scan_id"] == "test-scan-123"
        assert record["component"] == "STRANDS_AGENT"
        assert "event_id" in record
        assert "timestamp" in record


def test_event_logger_critical_events_flush(tmp_path: Path):
    """Boundary test: Critical events trigger immediate fsync/flush."""
    log_file = tmp_path / ".audit" / "events.jsonl"
    logger = EventLogger(log_file, scan_id="test-scan-crit")

    with patch("os.fsync") as mock_fsync:
        for crit_type in CRITICAL_EVENT_TYPES:
            logger.log("CIRCUIT_BREAKER", crit_type, {"trigger": "depth_exceeded"})

        assert mock_fsync.call_count == len(CRITICAL_EVENT_TYPES)


def test_event_logger_non_serializable_payload_boundary(tmp_path: Path):
    """Error boundary: Non-serializable payload converted safely without crashing."""
    log_file = tmp_path / ".audit" / "events.jsonl"
    logger = EventLogger(log_file, scan_id="test-scan-err")

    class UnserializableObject:
        pass

    record = logger.log("SYSTEM", "DEBUG", {"obj": UnserializableObject()})
    assert record is not None

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    data = json.loads(lines[-1])
    assert "obj" in data["payload"]
