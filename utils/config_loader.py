from typing import Dict
import json
import yaml

from mypy.dmypy.client import console_entry


class ConfigLoader:
    _cache: Dict[str, dict] = {}

    @staticmethod
    def load(path: str) -> dict:
        if path in ConfigLoader._cache:
            return ConfigLoader._cache[path]

        config = ConfigLoader._load_raw(path)
        
        ConfigLoader._cache[path] = config
        return config

    @staticmethod
    def _load_raw(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Config file '{path}' not found")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file '{path}': {str(e)}")
