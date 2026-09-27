"""Thread-safe, deduplicated priority queue for triaging candidate vulnerability paths."""

import heapq
import itertools
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class TriageItem:
    """An item queued for verification by LLM agents."""

    path_id: str
    priority: float
    data: Dict[str, Any] = field(default_factory=dict)


class TriageQueue:
    """Thread-safe priority queue prioritizing highest risk paths with SHA256 deduplication."""

    def __init__(self) -> None:
        self._heap: List[Any] = []
        self._counter = itertools.count()
        self._visited_paths: Set[str] = set()
        self._lock = threading.Lock()

    def push(self, item: TriageItem) -> bool:
        """Push item to priority queue if path_id has not already been queued."""
        with self._lock:
            if item.path_id in self._visited_paths:
                return False
            self._visited_paths.add(item.path_id)
            count = next(self._counter)
            # Store negative priority for max-heap behavior
            heapq.heappush(self._heap, (-item.priority, count, item))
            return True

    def pop(self) -> Optional[TriageItem]:
        """Pop and return the highest priority item from the queue, or None if empty."""
        with self._lock:
            if not self._heap:
                return None
            _neg_prio, _cnt, item = heapq.heappop(self._heap)
            return item

    def size(self) -> int:
        """Return number of remaining items in the queue."""
        with self._lock:
            return len(self._heap)

    def is_empty(self) -> bool:
        """Check whether the queue is empty."""
        with self._lock:
            return len(self._heap) == 0
