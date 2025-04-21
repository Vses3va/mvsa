import ast
from typing import List, Dict, Any, Set, Union
import logging

logger = logging.getLogger(__name__)

class XSSDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.unsafe_functions = {"mark_safe", "safe", "unescape", "html", "render"}
        self.unsafe_attributes = {"innerHTML", "outerHTML", "insertAdjacentHTML", "write"}
        self.user_input_sources = {
            "request.args", "request.form", "request.json",
            "request.cookies", "request.data", "request.headers",
            "input", "getattr", "os.environ", "sys.argv", "user_input"
        }
        self.html_tags = {"script", "div", "span", "img", "a", "style", "iframe"}

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in self.unsafe_functions:
            if self._has_user_input(node):
                self._report(
                    line=node.lineno,
                    details=f"Использование небезопасной функции: {node.func.id}"
                )

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.targets[0], ast.Attribute):
            if node.targets[0].attr in self.unsafe_attributes:
                if self._has_user_input(node.value):
                    self._report(
                        line=node.lineno,
                        details=f"Опасное присваивание в {node.targets[0].attr}"
                    )

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.Add):
            left_has_html = self._contains_html(node.left)
            right_has_html = self._contains_html(node.right)
            left_has_input = self._has_user_input(node.left)
            right_has_input = self._has_user_input(node.right)
            
            if (left_has_html and right_has_input) or (right_has_html and left_has_input):
                self._report(
                    line=node.lineno,
                    details=f"Конкатенация HTML с пользовательским вводом: {ast.unparse(node)}"
                )

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if self._contains_html(node) and self._has_user_input(node):
            self._report(
                line=node.lineno,
                details=f"f-строка с пользовательским вводом в HTML-контексте: {ast.unparse(node)}"
            )

    def _contains_html(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Str):
            text = node.s.lower()
            return any(f"<{tag}" in text or f"</{tag}" in text for tag in self.html_tags)
        
        if isinstance(node, ast.JoinedStr):
            full_text = ast.unparse(node).lower()
            if any(f"<{tag}" in full_text or f"</{tag}" in full_text for tag in self.html_tags):
                return True
            return any(self._contains_html(n) for n in node.values)
            
        return False

    def _has_user_input(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.user_input_sources:
                return True
            if isinstance(child, ast.Attribute):
                attr_path = self._get_attr_path(child)
                if any(src in attr_path for src in self.user_input_sources):
                    return True
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                if child.func.id in {"input", "getattr"}:
                    return True
        return False

    def _get_attr_path(self, node: ast.Attribute) -> str:
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        elif isinstance(node.value, ast.Attribute):
            return f"{self._get_attr_path(node.value)}.{node.attr}"
        return node.attr

    def _report(self, line: int, details: str) -> None:
        self.vulnerabilities.append({
            "type": "XSS",
            "line": line,
            "details": details,
        })
        logger.warning(f"Обнаружен XSS на строке {line}: {details}")
