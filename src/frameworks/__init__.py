"""Framework semantic identity and route/middleware resolvers."""

from src.frameworks.base import FrameworkEndpoint
from src.frameworks.detector import FrameworkDetector
from src.frameworks.express import ExpressResolver

__all__ = ["FrameworkEndpoint", "FrameworkDetector", "ExpressResolver"]
