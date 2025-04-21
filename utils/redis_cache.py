import json
from redis import Redis

class RedisCache:
    def __init__(self, client: Redis):
        self.client = client
    
    def get(self, key: str) -> List[Dict]:
        if data := self.client.get(key):
            return json.loads(data)
        return []
    
    def set(self, key: str, value: List[Dict]):
        self.client.set(key, json.dumps(value))