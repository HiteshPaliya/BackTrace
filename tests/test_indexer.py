"""Tests for Tree-Sitter Polyglot AST Indexer."""

from src.indexer.treesitter import TreeSitterIndexer


def test_treesitter_parses_python_and_js():
    """Happy path: Parse Python and JavaScript symbols and imports."""
    indexer = TreeSitterIndexer()

    py_code = """
import os
from sys import path

def authenticate_user(username, password):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query)

class AuthService:
    def verify_token(self, token):
        return True
"""
    py_res = indexer.index_source("auth.py", py_code, "python")
    func_names = [s.name for s in py_res.symbols]
    assert "authenticate_user" in func_names
    assert "AuthService" in func_names
    assert "verify_token" in func_names

    import_names = [imp.imported_name for imp in py_res.imports]
    assert "os" in import_names
    assert "path" in import_names

    # Check calls
    calls = [c.callee_name for c in py_res.calls]
    assert "db.execute" in calls or "execute" in calls

    # Test JavaScript
    js_code = """
import express from 'express';
const { exec } = require('child_process');

function handleRequest(req, res) {
    const cmd = req.query.cmd;
    exec(cmd);
}
"""
    js_res = indexer.index_source("server.js", js_code, "javascript")
    js_func_names = [s.name for s in js_res.symbols]
    assert "handleRequest" in js_func_names
    js_calls = [c.callee_name for c in js_res.calls]
    assert "exec" in js_calls


def test_treesitter_handles_syntax_errors_gracefully():
    """Boundary test: Invalid syntax containing ERROR nodes does not crash indexer."""
    indexer = TreeSitterIndexer()
    broken_code = """
def broken_func(
    # missing closing parenthesis and body
"""
    res = indexer.index_source("broken.py", broken_code, "python")
    assert res is not None
    assert isinstance(res.symbols, list)


def test_treesitter_unsupported_language_graceful():
    """Boundary test: Unsupported language does not crash indexer."""
    indexer = TreeSitterIndexer()
    res = indexer.index_source("doc.txt", "Some text", "plain_text")
    assert res is not None
    assert len(res.symbols) == 0
