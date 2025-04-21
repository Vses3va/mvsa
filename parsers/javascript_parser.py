import esprima
import logging

logger = logging.getLogger(__name__)

class JavaScriptParser:
    @staticmethod
    def parse(code: str) -> esprima.nodes.Script:
        try:
            return esprima.parseScript(code, {"range": True})
        except Exception as e:
            logger.error(f"Ошибка парсинга JavaScript: {e}")
            raise