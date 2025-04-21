import pytest
from mvsa import MVSA

# Тест для анализа Python-кода
def test_python_analysis():
    analyzer = MVSA()
    code = "cursor.execute('SELECT * FROM users WHERE id = ' + user_input)"
    results = analyzer.analyze(code, "python")
    assert any(vuln["type"] == "SQLi" for vuln in results)

# Тест для анализа JavaScript-кода
def test_javascript_analysis():
    analyzer = MVSA()
    code = "fetch('http://localhost/data')"
    results = analyzer.analyze(code, "javascript")
    assert any(vuln["type"] == "SSRF" for vuln in results)

# Тест для неподдерживаемого языка
def test_unsupported_language():
    analyzer = MVSA()
    results = analyzer.analyze("print('test')", "ruby")
    assert len(results) == 0
