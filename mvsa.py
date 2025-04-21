import argparse
import json
from pathlib import Path
import importlib
from typing import Dict, List
from detectors import (
      sqli_detector, xss_detector, ssrf_detector,
      csrf_detector, command_injection_detector, insecure_auth_detector
)
from parsers import python_parser, javascript_parser
from utils import config_loader, report_generator

class MVSA:
      def __init__(self, config_path: str = "config.yaml"):
          self.config = config_loader.ConfigLoader.load(config_path)
          self.parsers: Dict[str, object] = {
                "python": python_parser.PythonParser,
                "javascript": javascript_parser.JavaScriptParser
          }
          self.detectors = self._init_detectors()

      def _init_detectors(self) -> List[object]:
          detector_config = {
              "sqli": ("detectors.sqli_detector", "SQLiDetector"),
              "xss": ("detectors.xss_detector", "XSSDetector"),
              "csrf": ("detectors.csrf_detector", "CSRFDetector"),
              "ssrf": ("detectors.ssrf_detector", "SSRFDetector"),
              "command_injection": ("detectors.command_injection_detector", "CommandInjectionDetector"),
              "insecure_auth": ("detectors.insecure_auth_detector", "InsecureAuthDetector")
          }

          detectors = []
          for vuln in self.config.get("vulnerabilities", []):
              if vuln in detector_config:
                  module_name, class_name = detector_config[vuln]
                  module = importlib.import_module(module_name)
                  detector_class = getattr(module, class_name)
                  detectors.append(detector_class())
          return detectors

      def analyze(self, code: str, language: str) -> List[Dict]:
          vulnerabilities = []
          try:
              parser_class = self.parsers[language]
              tree = parser_class.parse(code)
              for detector in self.detectors:
                  detector.visit(tree)
                  vulnerabilities.extend(detector.vulnerabilities)
          except SyntaxError as e:
              print(f"Ошибка парсинга: {e}")
          except KeyError:
              print(f"Неподдерживаемый язык: {language}")
          return vulnerabilities

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MVSA: Анализатор уязвимостей")
    parser.add_argument("--code", help="Путь к файлу с кодом", required=True)
    parser.add_argument("--report", help="Путь для сохранения отчета", default="report.json")
    args = parser.parse_args()
      
    try:
        with open(args.code, "r", encoding='utf-8') as file:
            code = file.read()
    except FileNotFoundError:
        raise SystemExit(f"Файл {args.code} не найден!")
    analyzer = MVSA()
    language = "python" if args.code.endswith(".py") else "javascript"
    results = analyzer.analyze(code, language)
      
    report_generator.ReportGenerator.generate(results, args.report)
