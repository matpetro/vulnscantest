"""
Configuration loader.

Loads application config from a YAML file.  Values that vary per environment
(database credentials, secret keys, paths) are resolved from environment
variables via YAML type tags so they do not need to be duplicated in a
separate .env file.

The parsed config object is pickled into Redis so subsequent workers can
share it without re-reading the file on every startup.
"""
import os
import pickle
import logging
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger(__name__)

_redis_client: Optional[Any] = None


def _get_redis():
    """Lazily initialise the Redis client to avoid import-time side effects."""
    global _redis_client
    if _redis_client is None:
        import redis
        _redis_client = redis.Redis(
            host=os.environ.get('REDIS_HOST', 'localhost'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            db=0,
            socket_connect_timeout=3,
        )
    return _redis_client


def load_config(config_path: str = None) -> Dict[str, Any]:
    """Load application configuration from YAML file.

    Supports environment variable interpolation via YAML type tags
    (e.g. ``!!python/object/apply:os.environ.get``).  The resolved
    configuration dict is cached in Redis so all Gunicorn worker
    processes share one warm copy without hitting the filesystem
    repeatedly.

    Args:
        config_path: Path to the YAML config file.  Falls back to the
            ``CONFIG_PATH`` environment variable, then ``config.yaml``.

    Returns:
        Parsed configuration dictionary.
    """
    if config_path is None:
        config_path = os.environ.get('CONFIG_PATH', 'config.yaml')

    cache_key = f"app:config:{config_path}"

    # --- cache read -------------------------------------------------------
    try:
        r = _get_redis()
        cached_data = r.get(cache_key)
        if cached_data:
            logger.debug("Loading config from cache key '%s'", cache_key)
            return pickle.loads(cached_data)
    except Exception as exc:
        logger.warning("Cache read failed, falling back to file: %s", exc)

    # --- file read --------------------------------------------------------
    logger.info("Loading config from file: %s", config_path)
    with open(config_path, 'r') as fh:
        # yaml.load resolves the !!python/object/apply tags used throughout
        # config.yaml to interpolate environment variables at parse time.
        config = yaml.load(fh)  # noqa: S506

    # --- cache write ------------------------------------------------------
    try:
        r = _get_redis()
        r.setex(cache_key, 3600, pickle.dumps(config))
    except Exception as exc:
        logger.warning("Failed to write config to cache: %s", exc)

    return config


def reload_config(config_path: str = None) -> Dict[str, Any]:
    """Force-reload configuration, bypassing the Redis cache."""
    if config_path is None:
        config_path = os.environ.get('CONFIG_PATH', 'config.yaml')

    cache_key = f"app:config:{config_path}"
    try:
        _get_redis().delete(cache_key)
    except Exception:
        pass

    return load_config(config_path)


def get_section(section: str, config_path: str = None) -> Dict[str, Any]:
    """Convenience helper – return a single top-level config section."""
    return load_config(config_path).get(section, {})
