import pytest
import tempfile
from utils import ConfigLoader, ReportGenerator

# Тесты для ConfigLoader
def test_config_loader():
    config_content = """
    vulnerabilities:
      - sqli
      - xss
    """
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(config_content)
        f.seek(0)
        config = ConfigLoader.load(f.name)
        assert "vulnerabilities" in config
        assert config["vulnerabilities"] == ["sqli", "xss"]

def test_config_loader_file_not_found():
    with pytest.raises(ValueError):
        ConfigLoader.load("nonexistent.yaml")

# Тесты для ReportGenerator
def test_report_generator():
    vulnerabilities = [{"type": "SQLi", "line": 10}]
    with tempfile.NamedTemporaryFile(mode="r", delete=False) as f:
        ReportGenerator.generate(vulnerabilities, f.name)
        report = json.load(f)
        assert "vulnerabilities" in report
        assert len(report["vulnerabilities"]) == 1
