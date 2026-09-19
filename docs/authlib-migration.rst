Authlib migration
=================

The compatibility package now delegates OAuth 1 and OAuth 2 protocol handling
to Authlib. The public ``flask_oauthlib`` imports, remote-app registry,
``OAuthRemoteApp`` hooks and provider decorators remain available, but direct
imports of OAuthlib internals are no longer supported.

Cache configuration
-------------------

Authorization codes are stored through the initialized Invenio-Cache /
Flask-Caching extension. Use ``CACHE_TYPE`` with a Flask-Caching backend name,
for example ``RedisCache``, ``SimpleCache``, ``MemcachedCache`` or
``FileSystemCache``. Redis uses Flask-Caching's public ``CACHE_REDIS_URL`` or
``CACHE_REDIS_HOST``, ``CACHE_REDIS_PORT``, ``CACHE_REDIS_DB`` and
``CACHE_REDIS_PASSWORD`` settings, including their standard localhost defaults.
The old ``OAUTH2_CACHE_TYPE`` and ``OAUTH2_CACHE_REDIS_*`` settings are ignored;
in particular, do not rename
``OAUTH2_CACHE_TYPE`` to ``RedisCache`` because that option no longer selects a
backend.

Authorization codes use namespaced, bounded-lifetime cache entries and are
consumed once entirely through Invenio-Cache's public API. A bounded-lifetime
``add`` marker provides atomic one-time consumption on distributed backends such
as Redis and fails closed if a consumer is interrupted. SimpleCache remains
suitable for development and tests.

Protocol compatibility and security
-----------------------------------

OAuth 2 callback state is mandatory and validated by Authlib before a code is
exchanged. Authorization consent POSTs must match a validated consent GET in
the signed Flask session. Redirect URIs are validated before all success and
error redirects, and token exchange requires the original redirect URI when
one was recorded.

PKCE is optional for existing authorization-code clients. Clients that send a
``code_challenge`` may use ``plain`` or ``S256`` and must provide the matching
``code_verifier`` at the token endpoint. Existing clients that do not request
PKCE continue to work.

Legacy token transport can be disabled with
``OAUTH2_ALLOW_LEGACY_TOKEN_ENDPOINT_GET = False`` and
``OAUTH2_ALLOW_LEGACY_BEARER_TOKEN_TRANSPORT = False``. These settings enforce
POST token requests and Authorization-header bearer tokens. GET token requests
and query/form bearer tokens are retained only for compatibility and can leak
credentials through URLs, logs, and referrers.

OAuth 1 HMAC-SHA1 and RSA-SHA1 client signing are retained. ``rsa_key`` is
forwarded to Authlib's signer. OAuth 1 callbacks are bound to the request token
stored in the session and that token is consumed on callback.

Persisted data
--------------

No database migration is required. Existing client, bearer/refresh token,
remote-account and remote-token table formats are unchanged. Authorization
codes remain ephemeral cache data. Applications using the optional generic
SQLAlchemy grant binding must provide fields/repository behavior for any PKCE
challenge data they choose to support; Invenio's production binding uses the
cache repository.

Custom providers
----------------

Custom ``OAuthRemoteApp`` subclasses may continue to override ``authorize``,
``authorized_response``, ``expand_url``, ``make_client``, ``pre_request`` and
``http_request``. Token exchange uses the overridable HTTP hook only after
Authlib state validation succeeds.
