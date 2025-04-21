import ast
import logging
from typing import List, Dict, Any, Set, Union

logger = logging.getLogger(__name__)

class CommandInjectionDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.unsafe_functions: Set[str] = {
            'os.system', 'os.popen', 'subprocess.run',
            'subprocess.Popen', 'subprocess.call',
            'subprocess.check_output'
        }
        self.user_input_indicators: Set[str] = {
            'request.args', 'request.form', 'request.json',
            'request.cookies', 'input', 'sys.argv',
            'environ.get', 'flask.request'
        }

    def visit_Call(self, node: ast.Call) -> None:
        try:
            func_name = self._get_full_name(node.func)
            if func_name not in self.unsafe_functions:
                return

            for arg in node.args:
                if self._is_dangerous_argument(arg):
                    self._report_vulnerability(
                        line=node.lineno,
                        details=f"{func_name}: {ast.unparse(arg)}"
                    )

            for kw in node.keywords:
                if kw.arg == 'shell' and self._is_truthy(kw.value):
                    self._report_vulnerability(
                        line=node.lineno,
                        details="Опасный параметр shell=True"
                    )

        except Exception as e:
            logger.error(f"Ошибка анализа: {e}")

    def _get_full_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Attribute):
            return f"{self._get_full_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Call):
            return self._get_full_name(node.func)
        return ""

    def _is_dangerous_argument(self, node: ast.AST) -> bool:
        node_str = ast.unparse(node) if hasattr(ast, 'unparse') else ""

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'input':
            return True

        if isinstance(node, (ast.Attribute, ast.Name, ast.Subscript, ast.Call)):
            attr_path = self._get_full_name(node)
            if any(src in attr_path for src in self.user_input_indicators):
                return True

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._is_dangerous_argument(node.left) or self._is_dangerous_argument(node.right)

        if isinstance(node, ast.JoinedStr):
            return any(self._is_dangerous_value(value) for value in node.values if isinstance(value, ast.FormattedValue))

        if node_str and any(indicator in node_str for indicator in self.user_input_indicators):
            return True

        return False

    def _is_dangerous_value(self, node: ast.FormattedValue) -> bool:
        return self._is_dangerous_argument(node.value)

    def _is_truthy(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return node.value is True
        elif isinstance(node, ast.NameConstant):
            return node.value is True
        return False

    def _report_vulnerability(self, line: int, details: str) -> None:
        vuln = {
            "type": "Command Injection",
            "line": line,
            "details": details,
        }
        self.vulnerabilities.append(vuln)
        logger.warning(f"Обнаружена инъекция команд на строке {line}: {details}")
