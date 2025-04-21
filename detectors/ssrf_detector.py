import ast
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class SSRFDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.http_methods = {'get', 'post', 'put', 'delete', 'request', 'urlopen'}
        self.unsafe_libs = {'requests', 'httpx', 'aiohttp', 'urllib'}
        self.user_input_sources = {
            'request.args', 'request.form', 'request.json',
            'request.cookies', 'request.data', 'request.headers',
            'input', 'getattr', 'os.environ', 'sys.argv'
        }

    def visit_Call(self, node: ast.Call) -> None:
        try:
            if self._is_dangerous_call(node):
                self._analyze_arguments(node)
        except Exception as e:
            logger.error(f"Ошибка анализа: {e}")

    def _is_dangerous_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute):
            lib_name = self._get_full_attribute_name(node.func.value)
            return (node.func.attr in self.http_methods and 
                    any(lib in lib_name for lib in self.unsafe_libs))
        
        return isinstance(node.func, ast.Name) and node.func.id in self.http_methods

    def _get_full_attribute_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_full_attribute_name(node.value)}.{node.attr}"
        return ""

    def _analyze_arguments(self, node: ast.Call) -> None:
        for arg in node.args:
            if self._is_dangerous_argument(arg):
                self._report_vulnerability(
                    line=node.lineno,
                    details=f"Обнаружен SSRF в {ast.unparse(node.func)}: {ast.unparse(arg)}"
                )

        for kw in node.keywords:
            if kw.arg == 'url' and self._is_dangerous_argument(kw.value):
                self._report_vulnerability(
                    line=node.lineno,
                    details=f"Обнаружен SSRF в {ast.unparse(node.func)}: {ast.unparse(kw.value)}"
                )

    def _is_dangerous_argument(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
            
        if isinstance(node, ast.Subscript):
            return True
            
        if isinstance(node, ast.Name):
            return node.id in {'user_input', 'config'}
            
        if isinstance(node, ast.Call):
            return self._is_user_input_call(node)
            
        if isinstance(node, ast.Attribute):
            return self._is_user_input_attribute(node)
            
        return False

    def _is_user_input_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Name) and node.func.id == 'input':
            return True
            
        if isinstance(node.func, ast.Attribute):
            attr_path = self._get_full_attribute_name(node.func)
            return any(src in attr_path for src in self.user_input_sources)
            
        return False

    def _is_user_input_attribute(self, node: ast.Attribute) -> bool:
        attr_path = self._get_full_attribute_name(node)
        return any(src in attr_path for src in self.user_input_sources)

    def _report_vulnerability(self, line: int, details: str) -> None:
        self.vulnerabilities.append({
            "type": "SSRF",
            "line": line,
            "details": details,
        })
        logger.warning(f"Обнаружен SSRF на строке {line}: {details}")
