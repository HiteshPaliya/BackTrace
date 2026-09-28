"""Tests for Framework Semantic Detection and Express Route/Middleware Resolver."""

from pathlib import Path

from src.frameworks.detector import FrameworkDetector
from src.frameworks.express import ExpressResolver


def test_express_route_composition_and_middleware_inheritance(tmp_path: Path):
    """Happy path: Express resolver composes mounted prefixes and inherits global middleware."""
    app_js = tmp_path / "app.js"
    app_js.write_text(
        """
        const express = require('express');
        const app = express();
        const userRouter = require('./routes/users');
        app.use(authMiddleware);
        app.use('/api/v1', userRouter);
        """,
        encoding="utf-8",
    )

    routes_dir = tmp_path / "routes"
    routes_dir.mkdir(parents=True)
    users_js = routes_dir / "users.js"
    users_js.write_text(
        """
        const express = require('express');
        const router = express.Router();
        router.post('/login', loginController);
        module.exports = router;
        """,
        encoding="utf-8",
    )

    detector = FrameworkDetector(tmp_path)
    assert detector.identify() == "express"

    resolver = ExpressResolver(tmp_path)
    endpoints = resolver.resolve_endpoints()

    login_ep = next((e for e in endpoints if e.route_pattern == "/api/v1/login"), None)
    assert login_ep is not None
    assert login_ep.http_method == "POST"
    assert login_ep.auth_state == "REQUIRED"  # Inherited from app.use(authMiddleware)
    assert login_ep.handler_symbol == "loginController"


def test_express_unauthenticated_route(tmp_path: Path):
    """Boundary test: Public route without auth middleware resolves to NOT_REQUIRED or UNKNOWN."""
    server_js = tmp_path / "server.js"
    server_js.write_text(
        """
        const express = require('express');
        const app = express();
        app.get('/public/health', healthCheck);
        app.get('/custom', customGuard, customHandler);
        """,
        encoding="utf-8",
    )

    resolver = ExpressResolver(tmp_path)
    endpoints = resolver.resolve_endpoints()

    health_ep = next((e for e in endpoints if e.route_pattern == "/public/health"), None)
    assert health_ep is not None
    assert health_ep.auth_state == "NOT_REQUIRED"

    custom_ep = next((e for e in endpoints if e.route_pattern == "/custom"), None)
    assert custom_ep is not None
    assert custom_ep.auth_state == "UNKNOWN"
