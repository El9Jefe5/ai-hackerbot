"""Thin Redis queues. Jobs carry only an assessment id, never a host or a command."""
import json

import redis

from app.core.config import settings

SCAN_KEY = "hackerbot:assessments"
ANALYSIS_KEY = "hackerbot:analysis"


class RedisQueue:
    def __init__(self, url: str, key: str):
        self._r = redis.Redis.from_url(url)
        self._key = key

    def enqueue(self, assessment_id: int) -> None:
        self._r.lpush(self._key, json.dumps({"assessment_id": assessment_id}))

    def dequeue(self, timeout: int = 5) -> int | None:
        item = self._r.brpop([self._key], timeout=timeout)
        return json.loads(item[1])["assessment_id"] if item else None


_queues: dict[str, RedisQueue] = {}


def _get(key: str) -> RedisQueue:
    if key not in _queues:
        _queues[key] = RedisQueue(settings.redis_url, key)
    return _queues[key]


def get_queue() -> RedisQueue:
    return _get(SCAN_KEY)


def get_analysis_queue() -> RedisQueue:
    return _get(ANALYSIS_KEY)
