import ast
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class InsecureAuthDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.imports: Dict[str, str] = {}
        self.weak_algorithms = {'md5', 'sha1', 'crypt', 'des', 'rc4'}
        self.unsafe_auth_functions = {'getpass', 'compare_digest'}
        self.password_keywords = {'password', 'passwd', 'pwd', 'secret', 'ключ', 'пароль'}

    def visit(self, node: ast.AST) -> None:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            super().visit(node)
        else:
            super().visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ''
        for alias in node.names:
            full_name = f"{module}.{alias.name}"
            self.imports[alias.asname or alias.name] = full_name

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_plaintext_password(node)
        self._check_hardcoded_credentials(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_weak_hashing(node)
        self._check_unsafe_auth(node)

    def _check_plaintext_password(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in self.password_keywords:
                if isinstance(node.value, (ast.Str, ast.Constant)) and isinstance(node.value.value, str):
                    self._report(
                        line=node.lineno,
                        details=f"Пароль '{node.value.value}' хранится в открытом виде")

    def _check_hardcoded_credentials(self, node: ast.Assign) -> None:
        if isinstance(node.value, (ast.Str, ast.Constant)) and isinstance(node.value.value, str):
            value = node.value.value.lower()
            if any(cred in value for cred in ['admin', 'password', 'пароль']):
                self._report(
                    line=node.lineno,
                    details=f"Жестко заданные учетные данные: '{node.value.value}'")

    def _check_weak_hashing(self, node: ast.Call) -> None:
        func_name = self._get_full_func_name(node.func)
        if not func_name:
            return

        # Проверяем как hashlib.md5(), так и md5() при импорте
        algo = func_name.split('.')[-1].lower()
        if algo in self.weak_algorithms:
            self._report(
                line=node.lineno,
                details=f"Использование слабого алгоритма хеширования: {algo}")

    def _check_unsafe_auth(self, node: ast.Call) -> None:
        func_name = self._get_full_func_name(node.func)
        if not func_name:
            return

        func = func_name.split('.')[-1].lower()
        if func in self.unsafe_auth_functions:
            self._report(
                line=node.lineno,
                details=f"Использование небезопасной функции аутентификации: {func}")

    def _get_full_func_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return self.imports.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            base = self._get_full_func_name(node.value)
            return f"{base}.{node.attr}" if base else None
        elif isinstance(node, ast.Call):
            return self._get_full_func_name(node.func)
        return None

    def _report(self, line: int, details: str) -> None:
        vuln = {
            "type": "Insecure Authentication",
            "line": line,
            "details": details
        }
        self.vulnerabilities.append(vuln)
        logger.warning(f"Обнаружена небезопасная аутентификация на строке {line}: {details}")
