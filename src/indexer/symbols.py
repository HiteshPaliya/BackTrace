"""Data models representing parsed AST symbols, imports, and call sites."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ASTSymbol:
    """A declared symbol (function, method, class, variable)."""

    name: str
    kind: str  # 'FUNCTION', 'METHOD', 'CLASS', 'INTERFACE', 'VARIABLE'
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    signature: str = ""
    scope: Optional[str] = None


@dataclass
class ASTImport:
    """An imported module or symbol reference."""

    imported_name: str
    module_source: Optional[str] = None
    alias: Optional[str] = None
    line: int = 1


@dataclass
class ASTCall:
    """A detected callsite within an AST."""

    callee_name: str
    line: int
    col: int
    caller_scope: Optional[str] = None


@dataclass
class IndexResult:
    """Extracted symbols, imports, and calls from an individual source file."""

    symbols: List[ASTSymbol] = field(default_factory=list)
    imports: List[ASTImport] = field(default_factory=list)
    calls: List[ASTCall] = field(default_factory=list)
