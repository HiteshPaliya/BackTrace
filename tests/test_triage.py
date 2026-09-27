"""Tests for Composite Triage Scorer and Deduplicated Priority Queue."""

from src.triage.queue import TriageItem, TriageQueue
from src.triage.scorer import CompositeScorer


def test_composite_scoring_and_deduplication():
    """Happy path: Priority formula reflects severity/reachability/exposure and deduplicates."""
    score_high = CompositeScorer.calculate_priority(
        sink_severity="CRITICAL",
        reachability_confidence=0.9,
        is_unauthenticated=True,
        hop_count=2,
    )

    score_low = CompositeScorer.calculate_priority(
        sink_severity="LOW",
        reachability_confidence=0.5,
        is_unauthenticated=False,
        hop_count=8,
    )

    assert score_high > score_low

    queue = TriageQueue()
    queue.push(TriageItem(path_id="sha_1", priority=score_high, data={"val": 1}))
    queue.push(TriageItem(path_id="sha_1", priority=score_high, data={"val": 1}))  # Duplicate

    assert queue.size() == 1


def test_priority_queue_ordering():
    """Happy path: Items are popped in descending priority order."""
    queue = TriageQueue()
    queue.push(TriageItem(path_id="p1", priority=0.2, data={"name": "low"}))
    queue.push(TriageItem(path_id="p2", priority=0.9, data={"name": "high"}))
    queue.push(TriageItem(path_id="p3", priority=0.5, data={"name": "med"}))

    first = queue.pop()
    assert first is not None
    assert first.path_id == "p2"

    second = queue.pop()
    assert second is not None
    assert second.path_id == "p3"

    third = queue.pop()
    assert third is not None
    assert third.path_id == "p1"


def test_empty_queue_boundary():
    """Boundary test: Pop on empty queue returns None safely."""
    queue = TriageQueue()
    assert queue.is_empty() is True
    assert queue.pop() is None


def test_unknown_severity_fallback():
    """Boundary test: Unknown severity string falls back to 0.1 weight safely."""
    score = CompositeScorer.calculate_priority("UNKNOWN_SEV", 0.8, True, 1)
    assert score > 0.0
