import json
from datetime import datetime
from typing import Dict, List

class ReportGenerator:
      @staticmethod
      def generate(results: List[Dict], output_path: str) -> None:
          report = {
              "timestamp": datetime.now().isoformat(),
              "vulnerabilities": results
          }
          with open(output_path, "w", encoding='utf-8') as file:
              json.dump(report, file, indent=2, ensure_ascii=False)
