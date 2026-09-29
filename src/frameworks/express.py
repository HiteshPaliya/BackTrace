"""Express.js semantic route, prefix mounting, and middleware resolver."""

import re
from typing import Dict, List

from src.frameworks.base import BaseFrameworkResolver, FrameworkEndpoint


class ExpressResolver(BaseFrameworkResolver):
    """Resolves Express.js routes with prefix composition and middleware inheritance."""

    HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

    AUTH_KEYWORDS = {"auth", "jwt", "passport", "login", "authenticated", "session"}

    MOUNT_PATTERN = re.compile(
        r"""app\.use\s*\(\s*['"]([^'"]+)['"]\s*,\s*([a-zA-Z0-9_$]+)\s*\)"""
    )
    GLOBAL_MIDDLEWARE_PATTERN = re.compile(
        r"""app\.use\s*\(\s*([a-zA-Z0-9_$]+)\s*\)"""
    )
    ROUTER_DEF_PATTERN = re.compile(
        r"""(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    )
    ROUTE_CALL_PATTERN = re.compile(
        r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*,([^)]+)\)"""
    )
    CHAINED_ROUTE_PATTERN = re.compile(
        r"""(?:app|router)\.route\s*\(\s*['"]([^'"]+)['"]\s*\)((?:\s*\.(?:get|post|put|delete|patch)\s*\([^)]+\))+)"""
    )
    METHOD_CALL_PATTERN = re.compile(
        r"""\.(get|post|put|delete|patch)\s*\(([^)]+)\)"""
    )

    def resolve_endpoints(self) -> List[FrameworkEndpoint]:
        """Walk repository and deterministically resolve endpoints with prefix and middleware."""
        endpoints: List[FrameworkEndpoint] = []
        global_middleware: List[str] = []
        router_mounts: Dict[str, str] = {}  # var_name -> mount_prefix
        router_files: Dict[str, str] = {}   # var_name -> rel_path

        js_ts_files = [
            p
            for p in self.repo_path.rglob("*")
            if p.is_file()
            and p.suffix in [".js", ".ts"]
            and not any(part in ["node_modules", ".git", ".venv", "dist"] for part in p.parts)
        ]

        # Pass 1: Discover global middleware and router mounts in entry files
        for p in js_ts_files:
            try:
                code = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # Extract global middleware
            for match in self.GLOBAL_MIDDLEWARE_PATTERN.finditer(code):
                mw_name = match.group(1).strip()
                if mw_name != "express":
                    global_middleware.append(mw_name)

            # Extract router imports
            for match in self.ROUTER_DEF_PATTERN.finditer(code):
                var_name = match.group(1)
                import_path = match.group(2)
                router_files[var_name] = import_path

            # Extract router mounts
            for match in self.MOUNT_PATTERN.finditer(code):
                prefix = match.group(1).rstrip("/")
                router_var = match.group(2)
                router_mounts[router_var] = prefix

        # Map file paths to mounted prefixes
        path_prefix_map: Dict[str, str] = {}
        for var_name, prefix in router_mounts.items():
            rel_import = router_files.get(var_name)
            if rel_import:
                norm_import = rel_import.lstrip("./").replace("\\", "/")
                path_prefix_map[norm_import] = prefix

        # Pass 2: Extract routes from all files
        for p in js_ts_files:
            rel_path = str(p.relative_to(self.repo_path)).replace("\\", "/")
            base_name = p.stem
            # Check if this file has a mounted prefix
            prefix = ""
            for import_key, mount_pfx in path_prefix_map.items():
                if import_key in rel_path or base_name in import_key:
                    prefix = mount_pfx
                    break

            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for match in self.ROUTE_CALL_PATTERN.finditer(content):
                method = match.group(1).upper()
                route_subpath = match.group(2)
                args_str = match.group(3)

                composed_path = f"{prefix}/{route_subpath.lstrip('/')}"
                if not composed_path.startswith("/"):
                    composed_path = "/" + composed_path

                # Parse arguments (middleware + handler)
                arg_tokens = [a.strip() for a in args_str.split(",") if a.strip()]
                handler_symbol = arg_tokens[-1] if arg_tokens else None
                local_middleware = arg_tokens[:-1] if len(arg_tokens) > 1 else []

                all_middleware = list(global_middleware) + local_middleware
                auth_state = self._determine_auth_state(all_middleware)

                # Line number calculation
                line_no = content[: match.start()].count("\n") + 1

                endpoints.append(
                    FrameworkEndpoint(
                        http_method=method,
                        route_pattern=composed_path,
                        file_path=rel_path,
                        line_number=line_no,
                        handler_symbol=handler_symbol,
                        middleware=all_middleware,
                        auth_state=auth_state,
                    )
                )

            # Also check for chained router.route('/path').get(...).post(...)
            for match in self.CHAINED_ROUTE_PATTERN.finditer(content):
                route_subpath = match.group(1)
                chain_body = match.group(2)
                composed_path = f"{prefix}/{route_subpath.lstrip('/')}"
                if not composed_path.startswith("/"):
                    composed_path = "/" + composed_path

                for call_m in self.METHOD_CALL_PATTERN.finditer(chain_body):
                    method = call_m.group(1).upper()
                    args_str = call_m.group(2)
                    arg_tokens = [a.strip() for a in args_str.split(",") if a.strip()]
                    handler_symbol = arg_tokens[-1] if arg_tokens else None
                    local_middleware = arg_tokens[:-1] if len(arg_tokens) > 1 else []
                    all_middleware = list(global_middleware) + local_middleware
                    auth_state = self._determine_auth_state(all_middleware)
                    line_no = content[: match.start()].count("\n") + 1

                    endpoints.append(
                        FrameworkEndpoint(
                            http_method=method,
                            route_pattern=composed_path,
                            file_path=rel_path,
                            line_number=line_no,
                            handler_symbol=handler_symbol,
                            middleware=all_middleware,
                            auth_state=auth_state,
                        )
                    )

        return endpoints

    def _determine_auth_state(self, middleware_list: List[str]) -> str:
        """Classify authentication state into REQUIRED, NOT_REQUIRED, or UNKNOWN."""
        if not middleware_list:
            return "NOT_REQUIRED"

        for mw in middleware_list:
            mw_lower = mw.lower()
            if any(k in mw_lower for k in self.AUTH_KEYWORDS):
                return "REQUIRED"

        return "UNKNOWN"
