"""Tests for config_loader – verifies that YAML parsing and Redis caching work."""
import os
import tempfile
import textwrap

import pytest


def test_load_config_basic(tmp_path):
    """Plain YAML (no Python tags) should parse without error."""
    cfg_file = tmp_path / "test_config.yaml"
    cfg_file.write_text(textwrap.dedent("""\
        app:
          name: Test App
          debug: false
        database:
          host: localhost
          port: "5432"
    """))

    # Monkey-patch Redis to a no-op so the test does not need a real Redis server
    import app.config_loader as loader
    original_get_redis = loader._get_redis

    class _FakeRedis:
        def get(self, key): return None
        def setex(self, key, ttl, val): pass
        def delete(self, key): pass

    loader._get_redis = lambda: _FakeRedis()

    try:
        config = loader.load_config(str(cfg_file))
        assert config['app']['name'] == 'Test App'
        assert config['database']['host'] == 'localhost'
    finally:
        loader._get_redis = original_get_redis


def test_load_config_with_python_tags(tmp_path, monkeypatch):
    """Config that uses !!python/object/apply tags for env-var resolution."""
    monkeypatch.setenv('TEST_SECRET', 'my-secret-value')

    cfg_file = tmp_path / "tagged_config.yaml"
    cfg_file.write_text(textwrap.dedent("""\
        app:
          secret_key: !!python/object/apply:os.environ.get
            - TEST_SECRET
            - fallback
    """))

    import app.config_loader as loader

    class _FakeRedis:
        def get(self, key): return None
        def setex(self, key, ttl, val): pass

    loader._get_redis = lambda: _FakeRedis()

    config = loader.load_config(str(cfg_file))
    # The !!python/object/apply tag calls os.environ.get at parse time
    assert config['app']['secret_key'] == 'my-secret-value'


def test_reload_config_clears_cache(tmp_path, monkeypatch):
    """reload_config should bypass the Redis cache."""
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("app:\n  name: v1\n")

    import app.config_loader as loader
    deleted_keys = []

    class _FakeRedis:
        def get(self, key): return None
        def setex(self, key, ttl, val): pass
        def delete(self, key): deleted_keys.append(key)

    loader._get_redis = lambda: _FakeRedis()

    loader.reload_config(str(cfg_file))
    assert any('config' in k for k in deleted_keys), "Expected cache key to be deleted"
