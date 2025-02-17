import argparse
import json
from pathlib import Path
from detectors import (
    SQLiDetector, XSSDetector, SSRFDetector,
    CSRFDetector, CommandInjectionDetector, InsecureAuthDetector
)
from parsers import PythonParser, JavaScriptParser
from utils import ConfigLoader, ReportGenerator

class MVSA:
    def __init__(self, config_path: str = "config.yaml"):
        self.config = ConfigLoader.load(config_path)
        self.parsers = {
            "python": PythonParser(),
            "javascript": JavaScriptParser()
        }
        self.detectors = [
            SQLiDetector(),
            XSSDetector(),
            SSRFDetector(),
            CSRFDetector(),
            CommandInjectionDetector(),
            InsecureAuthDetector()
        ]

    def analyze(self, code: str, language: str) -> list:
        """Анализирует код на уязвимости."""
        vulnerabilities = []
        try:
            tree = self.parsers[language].parse(code)
            for detector in self.detectors:
                detector.visit(tree)
                vulnerabilities.extend(detector.vulnerabilities)
        except Exception as e:
            print(f"Ошибка анализа: {e}")
        return vulnerabilities

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MVSA: Анализатор уязвимостей")
    parser.add_argument("--code", help="Путь к файлу с кодом", required=True)
    parser.add_argument("--report", help="Путь для сохранения отчета", default="report.json")
    args = parser.parse_args()

    with open(args.code, "r") as file:
        code = file.read()

    analyzer = MVSA()
    language = "python" if args.code.endswith(".py") else "javascript"
    results = analyzer.analyze(code, language)

    ReportGenerator.generate(results, args.report)
import ast

class SQLiDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            for arg in node.args:
                if self._is_unsafe_concat(arg):
                    self.vulnerabilities.append({
                        "type": "SQLi",
                        "line": node.lineno,
                        "details": "Конкатенация строк в SQL-запросе"
                    })

    def _is_unsafe_concat(self, node) -> bool:
        return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
import ast

class XSSDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Assign(self, node):
        if isinstance(node.targets[0], ast.Attribute) and node.targets[0].attr == "innerHTML":
            self.vulnerabilities.append({
                "type": "XSS",
                "line": node.lineno,
                "details": "Присваивание user_input в innerHTML"
            })
import ast
from urllib.parse import urlparse

class SSRFDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            for arg in node.args:
                if isinstance(arg, ast.Constant) and self._is_localhost(arg.value):
                    self.vulnerabilities.append({
                        "type": "SSRF",
                        "line": node.lineno,
                        "details": "Запрос к локальному хосту"
                    })

    def _is_localhost(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.hostname in ["localhost", "127.0.0.1"]

import ast

class CSRFDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_FunctionDef(self, node):
        """Проверяет отсутствие CSRF-токена в POST-запросах."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and decorator.func.attr == "route":
                for kw in decorator.keywords:
                    if kw.arg == "methods" and "POST" in [m.s for m in kw.value.elts]:
                        if not self._has_csrf_token(node):
                            self.vulnerabilities.append({
                                "type": "CSRF",
                                "line": node.lineno,
                                "details": "Отсутствует CSRF-токен"
                            })

    def _has_csrf_token(self, node) -> bool:
        """Проверяет наличие CSRF-токена в функции."""
        for statement in node.body:
            if isinstance(statement, ast.If) and "csrf_token" in ast.dump(statement):
                return True
        return False
import ast

class CommandInjectionDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        """Обнаруживает вызовы os.system с конкатенацией строк."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
            for arg in node.args:
                if self._is_unsafe_concat(arg):
                    self.vulnerabilities.append({
                        "type": "Command Injection",
                        "line": node.lineno,
                        "details": "Опасная конкатенация в системной команде"
                    })

    def _is_unsafe_concat(self, node) -> bool:
        """Проверяет, используется ли конкатенация строк."""
        return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
    import ast

class InsecureAuthDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Assign(self, node):
        """Обнаруживает хранение паролей в открытом виде."""
        if isinstance(node.targets[0], ast.Name) and node.targets[0].id == "password":
            self.vulnerabilities.append({
                "type": "Insecure Authentication",
                "line": node.lineno,
                "details": "Пароль хранится в открытом виде"
            })
    import ast

class PythonParser:
    @staticmethod
    def parse(code: str) -> ast.AST:
        """Преобразует код в AST."""
        return ast.parse(code)
import json
from datetime import datetime

class ReportGenerator:
    @staticmethod
    def generate(vulnerabilities: list, path: str) -> None:
        report = {
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities
        }
        with open(path, "w") as file:
            json.dump(report, file, indent=2)
languages:
  - python
  - javascript

vulnerabilities:
  - sqli
  - xss
  - csrf
  - ssrf
  - command_injection
  - insecure_auth

report:
  format: json
  path: ./reports
import yaml

class ConfigLoader:
    @staticmethod
    def load(path: str) -> dict:
        """Загружает конфигурацию из YAML-файла."""
        with open(path, "r") as file:
            return yaml.safe_load(file)
import esprima

class JavaScriptParser:
    @staticmethod
    def parse(code: str) -> dict:
        """Преобразует JavaScript-код в AST."""
        return esprima.parseScript(code)
name: Security Check
on: [push, pull_request]

jobs:
  mvsa-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"
      - name: Run MVSA
        run: |
          pip install -r requirements.txt
          python mvsa.py --code=app.py --report=security_report.json
