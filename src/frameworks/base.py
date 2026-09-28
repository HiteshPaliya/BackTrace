"""Base models and interfaces for framework semantic resolvers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class FrameworkEndpoint:
    """Discovered HTTP endpoint with composed routing and middleware context."""

    http_method: str
    route_pattern: str
    file_path: str
    line_number: int
    handler_symbol: Optional[str]
    middleware: List[str] = field(default_factory=list)
    auth_state: str = "UNKNOWN"  # 'REQUIRED', 'NOT_REQUIRED', 'UNKNOWN'


class BaseFrameworkResolver(ABC):
    """Abstract interface for framework-specific route and middleware resolution."""

    def __init__(self, repo_path: Path | str) -> None:
        self.repo_path = Path(repo_path).resolve()

    @abstractmethod
    def resolve_endpoints(self) -> List[FrameworkEndpoint]:
        """Resolve all endpoints in the target repository."""
        pass
