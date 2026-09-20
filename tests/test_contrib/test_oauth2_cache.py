# coding: utf-8

from concurrent.futures import ThreadPoolExecutor

from flask import Flask
from invenio_cache import InvenioCache

from flask_oauthlib.contrib.oauth2 import bind_cache_grant


class Provider:
    def grantsetter(self, func):
        self.set_grant = func
        return func

    def grantgetter(self, func):
        self.get_grant = func
        return func


class Request:
    redirect_uri = "http://localhost/authorized"
    scopes = ["email"]


def current_user():
    return "user-1"


def create_provider(cache_type, **config):
    app = Flask(__name__)
    app.config.update(
        CACHE_TYPE=cache_type,
        OAUTH2_GRANT_CACHE_KEY_PREFIX="oauth2::test-grant::",
        **config,
    )
    InvenioCache(app)
    provider = Provider()
    bind_cache_grant(app, provider, current_user)
    return app, provider


def assert_grant_is_consumed(provider):
    provider.set_grant("client", {"code": "code-1"}, Request())

    grant = provider.get_grant("client", "code-1")
    assert grant is not None
    assert grant.client_id == "client"
    assert grant.code == "code-1"
    assert grant.redirect_uri == "http://localhost/authorized"
    assert grant.get_scope() == "email"

    assert provider.get_grant("client", "code-1") is None


def test_simple_cache_grant_is_consumed_once():
    app, provider = create_provider("SimpleCache")
    with app.app_context():
        assert_grant_is_consumed(provider)


def test_redis_cache_grant_is_consumed_once():
    app, provider = create_provider("RedisCache")
    with app.app_context():
        assert_grant_is_consumed(provider)


def test_redis_cache_grant_is_consumed_atomically():
    app, provider = create_provider("RedisCache")
    with app.app_context():
        provider.set_grant("client", {"code": "concurrent-code"}, Request())

    def consume_grant(_):
        with app.app_context():
            return provider.get_grant("client", "concurrent-code")

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(consume_grant, range(8)))

    assert sum(result is not None for result in results) == 1
