import ast

class PythonParser:
      @staticmethod
      def parse(code: str) -> ast.AST:
          try:
              return ast.parse(code)
          except SyntaxError as e:
              raise ValueError(f"Ошибка парсинга: {e}")