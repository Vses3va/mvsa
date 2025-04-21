import ast
import logging
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)

class CSRFDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self._protection_decorators: Set[str] = {
            'csrf_protect', 'ensure_csrf_cookie',
            'requires_csrf_token', 'csrf_protection',
            'csrf_required', 'validate_csrf'
        }

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        is_post = False
        has_protection = False

        for decorator in node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)
            
            if decorator_name == 'route':
                is_post = self._is_post_route(decorator)
            elif decorator_name in {'post', 'put', 'delete'}:
                is_post = True
            
            if decorator_name in self._protection_decorators:
                has_protection = True
        
        if is_post and not has_protection:
            self._report_vulnerability(
                line=node.lineno,
                details=f"POST-метод '{node.name}' без CSRF-защиты"
            )

    def _get_decorator_name(self, decorator: ast.AST) -> str:
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            return decorator.attr
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return ''

    def _is_post_route(self, decorator: ast.Call) -> bool:
        for kw in decorator.keywords:
            if kw.arg == 'methods' and isinstance(kw.value, ast.List):
                return any(isinstance(el, ast.Str) and el.s.upper() == 'POST'
                         for el in kw.value.elts)
        return False

    def _report_vulnerability(self, line: int, details: str) -> None:
        self.vulnerabilities.append({
            "type": "CSRF",
            "line": line,
            "details": details,
        })
        logger.warning(f"Обнаружена CSRF уязвимость на строке {line}: {details}")
