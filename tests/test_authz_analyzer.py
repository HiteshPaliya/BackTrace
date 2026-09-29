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


def test_authz_analyzer_detects_unscoped_findone_in_juiceshop_basket():
    """Invariants: BasketModel.findOne({ where: { id } }) flags CANDIDATE_AUTHZ_GAP."""
    analyzer = AuthorizationAnalyzer()
    juice_basket_code = """
        export function retrieveBasket () {
          return async (req: Request, res: Response, next: NextFunction) => {
            const id = req.params.id;
            const basket = await BasketModel.findOne({ where: { id } });
            res.json(utils.queryResultToJson(basket));
          }
        }
    """
    res = analyzer.analyze_handler("GET", "/rest/basket/:id", juice_basket_code, "typescript")
    assert res.has_gap is True
    assert res.gap_type == "CANDIDATE_AUTHZ_GAP"
    assert res.object_key == "req.params.id"


def test_authz_analyzer_tenant_and_role_relationships():
    """Spec 6.2: Analyzes TENANT scoping, ROLE-based checks, and query-param object keys."""
    analyzer = AuthorizationAnalyzer()

    # Tenant-scoped query
    tenant_code = """
        function getInvoice(req, res) {
            const invoiceId = req.query.invoiceId;
            Invoice.findOne({ where: { id: invoiceId, tenantId: req.user.tenantId } }).then(inv => {
                res.json(inv);
            });
        }
    """
    tenant_res = analyzer.analyze_handler("GET", "/invoice", tenant_code, "javascript")
    assert tenant_res.has_gap is False
    assert tenant_res.status == "AUTHZ_CONSTRAINT_PRESENT"
    assert tenant_res.relationship_type == "TENANT"

    # Role-based admin guard
    role_code = """
        function deleteAccount(req, res) {
            const userId = req.body.userId;
            if (req.user.role !== 'admin') {
                return res.status(403).send("Admin only");
            }
            Account.destroy({ where: { id: userId } });
        }
    """
    role_res = analyzer.analyze_handler("POST", "/account/delete", role_code, "javascript")
    assert role_res.has_gap is False
    assert role_res.status == "AUTHZ_CONSTRAINT_PRESENT"
    assert role_res.relationship_type == "ROLE"


