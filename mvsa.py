import ast
import requests
from urllib.parse import urlparse

class VulnerabilityDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        # Поиск SQL-инъекций
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            self._check_sql_injection(node)
        # Поиск XSS
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'innerHTML':
            self._check_xss(node)
        # Поиск инъекций команд
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'system':
            self._check_command_injection(node)
        # Поиск SSRF
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'get':
            self._check_ssrf(node)

    def _check_sql_injection(self, node):
        for arg in node.args:
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                self.vulnerabilities.append({
                    'type': 'SQL-инъекция',
                    'line': node.lineno,
                    'details': 'Конкатенация строк в SQL-запросе'
                })

    def _check_xss(self, node):
        if isinstance(node.value, ast.Name):
            self.vulnerabilities.append({
                'type': 'XSS',
                'line': node.lineno,
                'details': 'Присваивание user_input в innerHTML'
            })

    def _check_command_injection(self, node):
        for arg in node.args:
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                self.vulnerabilities.append({
                    'type': 'Инъекция команд',
                    'line': node.lineno,
                    'details': 'Опасная конкатенация в системной команде'
                })

    def _check_ssrf(self, node):
        for arg in node.args:
            if isinstance(arg, ast.Constant):
                parsed_url = urlparse(arg.value)
                if parsed_url.hostname in ["localhost", "127.0.0.1"]:
                    self.vulnerabilities.append({
                        'type': 'SSRF',
                        'line': node.lineno,
                        'details': 'Попытка доступа к локальному хосту'
                    })

def analyze_code(code):
    tree = ast.parse(code)
    detector = VulnerabilityDetector()
    detector.visit(tree)
    return detector.vulnerabilities

# Пример использования
if name == "__main__":
    with open("app.py", "r") as file:
        code = file.read()
        results = analyze_code(code)
        print(json.dumps(results, indent=2))
