import pytest
from parsers import PythonParser, JavaScriptParser

def test_python_parser():
    code = "print('Hello, World!')"
    parser = PythonParser()
    tree = parser.parse(code)
    assert isinstance(tree, ast.AST)

def test_javascript_parser():
    code = "console.log('Hello, World!');"
    parser = JavaScriptParser()
    tree = parser.parse(code)
    assert "body" in tree.toDict()  # Проверка структуры AST от esprima
