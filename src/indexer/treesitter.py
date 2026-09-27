"""Polyglot Tree-sitter AST indexer extracting symbols, imports, and calls."""

import warnings
from pathlib import Path
from typing import Dict, List, Optional

from src.indexer.symbols import ASTCall, ASTImport, ASTSymbol, IndexResult

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        import tree_sitter_languages
    except ImportError:
        tree_sitter_languages = None


class TreeSitterIndexer:
    """Extracts semantic symbols, cross-module imports, and call sites from code."""

    LANG_MAP: Dict[str, str] = {
        "python": "python",
        "javascript": "javascript",
        "typescript": "typescript",
        "go": "go",
        "java": "java",
        "ruby": "ruby",
        "php": "php",
    }

    def __init__(self) -> None:
        self.parsers = {}
        if tree_sitter_languages:
            for lang_key, lang_name in self.LANG_MAP.items():
                try:
                    self.parsers[lang_key] = tree_sitter_languages.get_parser(lang_name)
                except Exception:
                    pass

    def index_source(
        self,
        file_path: Path | str,
        code: str,
        language: Optional[str],
    ) -> IndexResult:
        """Parse source code with Tree-sitter and extract symbols, imports, and calls."""
        if not language or language not in self.parsers:
            return IndexResult()

        parser = self.parsers[language]
        try:
            tree = parser.parse(bytes(code, "utf-8", errors="replace"))
        except Exception:
            return IndexResult()

        symbols: List[ASTSymbol] = []
        imports: List[ASTImport] = []
        calls: List[ASTCall] = []

        self._walk_node(
            tree.root_node,
            code,
            language,
            symbols,
            imports,
            calls,
            current_scope="global",
        )

        return IndexResult(symbols=symbols, imports=imports, calls=calls)

    def _walk_node(
        self,
        node,
        code: str,
        language: str,
        symbols: List[ASTSymbol],
        imports: List[ASTImport],
        calls: List[ASTCall],
        current_scope: str,
    ) -> None:
        if node.type == "ERROR":
            # Tolerate syntax error CST nodes without stopping traversal
            for child in node.children:
                self._walk_node(child, code, language, symbols, imports, calls, current_scope)
            return

        # 1. Functions & Methods
        if node.type in (
            "function_definition",
            "function_declaration",
            "method_definition",
            "function_item",
        ):
            name = None
            for child in node.children:
                if child.type in ("identifier", "property_identifier", "name"):
                    name = code[child.start_byte : child.end_byte]
                    break

            if name:
                is_method = current_scope != "global" and node.type == "method_definition"
                kind = "METHOD" if is_method else "FUNCTION"
                snippet = code[node.start_byte : min(node.start_byte + 200, node.end_byte)]
                symbols.append(
                    ASTSymbol(
                        name=name,
                        kind=kind,
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                        end_line=node.end_point[0] + 1,
                        end_col=node.end_point[1],
                        signature=snippet.strip(),
                        scope=current_scope,
                    )
                )
                new_scope = f"{current_scope}.{name}" if current_scope != "global" else name
                for child in node.children:
                    self._walk_node(child, code, language, symbols, imports, calls, new_scope)
                return

        # 2. Classes
        if node.type in ("class_definition", "class_declaration", "class_specifier"):
            name = None
            for child in node.children:
                if child.type in ("identifier", "type_identifier", "name"):
                    name = code[child.start_byte : child.end_byte]
                    break

            if name:
                sig_snippet = code[
                    node.start_byte : min(node.start_byte + 100, node.end_byte)
                ].strip()
                symbols.append(
                    ASTSymbol(
                        name=name,
                        kind="CLASS",
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                        end_line=node.end_point[0] + 1,
                        end_col=node.end_point[1],
                        signature=sig_snippet,
                        scope=current_scope,
                    )
                )
                new_scope = f"{current_scope}.{name}" if current_scope != "global" else name
                for child in node.children:
                    self._walk_node(child, code, language, symbols, imports, calls, new_scope)
                return

        # 3. Imports
        if node.type in ("import_statement", "import_from_statement", "import_declaration"):
            raw_import = code[node.start_byte : node.end_byte].strip()
            # Extract basic imported identifiers
            for child in node.children:
                if child.type in ("dotted_name", "identifier", "import_specifier"):
                    import_text = code[child.start_byte : child.end_byte]
                    imports.append(
                        ASTImport(
                            imported_name=import_text,
                            module_source=raw_import,
                            line=node.start_point[0] + 1,
                        )
                    )

        # 4. Calls
        if node.type in ("call", "call_expression"):
            callee_node = node.children[0] if node.children else None
            if callee_node:
                callee_name = code[callee_node.start_byte : callee_node.end_byte].strip()
                calls.append(
                    ASTCall(
                        callee_name=callee_name,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        caller_scope=current_scope,
                    )
                )

        # Recurse children
        for child in node.children:
            self._walk_node(child, code, language, symbols, imports, calls, current_scope)
