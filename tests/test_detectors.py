import ast
import pytest
import sys
from pathlib import Path

# Добавляем корень проекта в PYTHONPATH
sys.path.append(str(Path(__file__).parent.parent))

from mvsa.detectors.sqli_detector import SQLiDetector
from mvsa.detectors.xss_detector import XSSDetector
from mvsa.detectors.ssrf_detector import SSRFDetector
from mvsa.detectors.csrf_detector import CSRFDetector
from mvsa.detectors.command_injection_detector import CommandInjectionDetector
from mvsa.detectors.insecure_auth_detector import InsecureAuthDetector

# Фикстуры для тестовых данных
@pytest.fixture
def sample_sqli_code():
    return "cursor.execute('SELECT * FROM users WHERE id = ' + user_input)"

@pytest.fixture
def sample_xss_code():
    return "document.getElementById('content').innerHTML = user_input"

@pytest.fixture
def sample_ssrf_code():
    return "requests.get('http://localhost/admin')"

@pytest.fixture
def sample_csrf_code():
    return """
    @app.route('/transfer', methods=['POST'])
    def transfer():
        pass
    """

@pytest.fixture
def sample_command_injection_code():
    return "os.system('ping ' + user_input)"

@pytest.fixture
def sample_insecure_auth_code():
    return "password = 'qwerty123'"

# Тесты для SQLiDetector
def test_sqli_detector(sample_sqli_code):
    detector = SQLiDetector()
    tree = ast.parse(sample_sqli_code)
    detector.visit(tree)
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["type"] == "SQLi"

# Тесты для XSSDetector
def test_xss_detector(sample_xss_code):
    detector = XSSDetector()
    tree = ast.parse(sample_xss_code)
    detector.visit(tree)
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["type"] == "XSS"

# Тесты для SSRFDetector
def test_ssrf_detector(sample_ssrf_code):
    detector = SSRFDetector()
    tree = ast.parse(sample_ssrf_code)
    detector.visit(tree)
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["type"] == "SSRF"

# Тесты для CSRFDetector
def test_csrf_detector(sample_csrf_code):
    detector = CSRFDetector()
    tree = ast.parse(sample_csrf_code)
    detector.visit(tree)
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["type"] == "CSRF"

# Тесты для CommandInjectionDetector
def test_command_injection_detector(sample_command_injection_code):
    detector = CommandInjectionDetector()
    tree = ast.parse(sample_command_injection_code)
    detector.visit(tree)
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["type"] == "Command Injection"

# Тесты для InsecureAuthDetector
def test_insecure_auth_detector(sample_insecure_auth_code):
    detector = InsecureAuthDetector()
    tree = ast.parse(sample_insecure_auth_code)
    detector.visit(tree)
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["type"] == "Insecure Authentication"
