"""Tests for Track B Authorization Relationship Analyzer (BOLA/IDOR)."""

from src.semantic.authz import AuthorizationAnalyzer


def test_authz_analyzer_detects_bola_and_scoped_queries():
    """Happy path: Flags unscoped findByPk and marks scoped queries as constrained."""
    analyzer = AuthorizationAnalyzer()

    # Case 1: Unscoped lookup without ownership check (Juice Shop Basket scenario)
    vulnerable_route = """
        function getBasket(req, res) {
            const basketId = req.params.id;
            Basket.findByPk(basketId).then(basket => {
                res.json(basket);
            });
        }
    """
    vuln_result = analyzer.analyze_handler(
        "GET", "/rest/basket/:id", vulnerable_route, "javascript"
    )
    assert vuln_result.has_gap is True
    assert vuln_result.gap_type == "CANDIDATE_AUTHZ_GAP"
    assert vuln_result.object_key == "req.params.id"

    # Case 2: Scoped lookup binding principal ownership directly in query
    safe_route = """
        function getBasket(req, res) {
            const basketId = req.params.id;
            Basket.findOne({ where: { id: basketId, UserId: req.user.id } }).then(basket => {
                res.json(basket);
            });
        }
    """
    safe_result = analyzer.analyze_handler("GET", "/rest/basket/:id", safe_route, "javascript")
    assert safe_result.has_gap is False
    assert safe_result.status == "AUTHZ_CONSTRAINT_PRESENT"


def test_authz_analyzer_detects_post_fetch_guard():
    """Happy path: Post-fetch ownership check prevents BOLA/IDOR gap."""
    analyzer = AuthorizationAnalyzer()
    guarded_route = """
        function getOrder(req, res) {
            const orderId = req.params.id;
            Order.findByPk(orderId).then(order => {
                if (order.UserId !== req.user.id) {
                    return res.status(403).send("Forbidden");
                }
                res.json(order);
            });
        }
    """
    result = analyzer.analyze_handler("GET", "/rest/order/:id", guarded_route, "javascript")
    assert result.has_gap is False
    assert result.status == "AUTHZ_CONSTRAINT_PRESENT"


def test_authz_analyzer_handles_no_object_key():
    """Boundary test: Route without resource object identifier has no BOLA gap."""
    analyzer = AuthorizationAnalyzer()
    route = "function health(req, res) { res.send('ok'); }"
    result = analyzer.analyze_handler("GET", "/health", route, "javascript")
    assert result.has_gap is False
