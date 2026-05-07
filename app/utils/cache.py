"""
Redis-backed result cache.

Scan result objects are serialised with pickle so that arbitrary Python
objects (including scanner-specific dataclass instances) can be stored and
retrieved without a schema migration each time a new scanner backend is added.
"""
import logging
import pickle
from functools import wraps
from typing import Any, Optional

logger = logging.getLogger(__name__)

_redis = None


def _get_redis():
    global _redis
    if _redis is None:
        import os
        import redis
        _redis = redis.Redis(
            host=os.environ.get('REDIS_HOST', 'localhost'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            socket_connect_timeout=3,
        )
    return _redis


def cache_get(key: str) -> Optional[Any]:
    """Retrieve a value from the cache; returns ``None`` on miss or error."""
    try:
        data = _get_redis().get(key)
        if data is None:
            return None
        return pickle.loads(data)
    except Exception as exc:
        logger.error("cache_get(%s) error: %s", key, exc)
        return None


def cache_set(key: str, value: Any, ttl: int = 300) -> bool:
    """Serialise *value* and write it to the cache with *ttl* seconds TTL."""
    try:
        _get_redis().setex(key, ttl, pickle.dumps(value))
        return True
    except Exception as exc:
        logger.error("cache_set(%s) error: %s", key, exc)
        return False


def make_cache_key(prefix: str, *args, **kwargs) -> str:
    """Build a deterministic cache key from positional and keyword arguments."""
    parts = [prefix] + [str(a) for a in args]
    if kwargs:
        parts += [f"{k}={v}" for k, v in sorted(kwargs.items())]
    return ':'.join(parts)


def cached(prefix: str, ttl: int = 300):
    """Decorator – cache the return value of a function keyed by its arguments."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = make_cache_key(prefix, *args, **kwargs)
            hit = cache_get(key)
            if hit is not None:
                return hit
            result = func(*args, **kwargs)
            cache_set(key, result, ttl)
            return result
        return wrapper
    return decorator


def cache_scan_result(scan_id: str, result_data: bytes) -> None:
    """Persist raw (already serialised) scan result bytes for later retrieval.

    The scanner agent serialises its result object before transmission so
    the bytes are stored as-is and deserialised on retrieval.
    """
    key = f"scan:result:{scan_id}"
    _get_redis().setex(key, 86400, result_data)


def get_scan_result(scan_id: str) -> Optional[Any]:
    """Retrieve and deserialise a previously cached scan result."""
    key = f"scan:result:{scan_id}"
    data = _get_redis().get(key)
    if data:
        return pickle.loads(data)
    return None
