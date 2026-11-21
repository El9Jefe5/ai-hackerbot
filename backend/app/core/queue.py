"""Thin Redis queue. Jobs carry only an assessment id, never a host or a command."""
import json

import redis

from app.core.config import settings

QUEUE_KEY = "hackerbot:assessments"


class RedisQueue:
    def __init__(self, url: str):
        self._r = redis.Redis.from_url(url)

    def enqueue(self, assessment_id: int) -> None:
        self._r.lpush(QUEUE_KEY, json.dumps({"assessment_id": assessment_id}))

    def dequeue(self, timeout: int = 5) -> int | None:
        item = self._r.brpop([QUEUE_KEY], timeout=timeout)
        return json.loads(item[1])["assessment_id"] if item else None


_queue: RedisQueue | None = None


def get_queue() -> RedisQueue:
    global _queue
    if _queue is None:
        _queue = RedisQueue(settings.redis_url)
    return _queue
