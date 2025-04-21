import ast
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class SQLiDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.unsafe_methods = {'execute', 'executemany', 'callproc', 'executescript'}
        self.db_api_names = {'cursor', 'connection', 'conn', 'db'}
        self.user_input_sources = {
            'request.args', 'request.form', 'request.json',
            'request.cookies', 'input', 'sys.argv',
            'environ.get', 'flask.request'
        }

    def visit_Call(self, node: ast.Call) -> None:
        try:
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in self.unsafe_methods:
                    if self._is_db_api_call(node.func.value):
                        if self._is_unsafe_query(node):
                            self._report_vulnerability(
                                line=node.lineno,
                                details="Использование небезопасного SQL-запроса")

            if isinstance(node.func, ast.Name) and node.func.id in self.unsafe_methods:
                if self._is_unsafe_query(node):
                    self._report_vulnerability(
                        line=node.lineno,
                        details="Прямой вызов опасного метода")

        except Exception as e:
            logger.error(f"Ошибка анализа SQLi: {e}")

    def _is_db_api_call(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.db_api_names
        elif isinstance(node, ast.Attribute):
            return self._is_db_api_call(node.value)
        return False

    def _is_unsafe_query(self, node: ast.Call) -> bool:
        for arg in node.args:
            if self._contains_user_input(arg) or self._has_string_operations(arg):
                return True
        return False

    def _contains_user_input(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.Name, ast.Attribute)):
            node_str = self._node_to_str(node)
            return any(source in node_str for source in self.user_input_sources)
        return False

    def _has_string_operations(self, node: ast.AST) -> bool:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        
        if isinstance(node, ast.JoinedStr):
            return True
            
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ('format', 'replace', 'join'):
                return True
                
        for field in ast.iter_fields(node):
            if isinstance(field[1], ast.AST) and self._has_string_operations(field[1]):
                return True
            elif isinstance(field[1], list):
                for item in field[1]:
                    if isinstance(item, ast.AST) and self._has_string_operations(item):
                        return True
                        
        return False

    def _node_to_str(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._node_to_str(node.value)}.{node.attr}"
        return ""

    def _report_vulnerability(self, line: int, details: str) -> None:
        self.vulnerabilities.append({
            "type": "SQL Injection",
            "line": line,
            "details": details
        })
        logger.warning(f"Обнаружена SQLi уязвимость на строке {line}: {details}")
