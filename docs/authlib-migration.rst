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
``FileSystemCache``. Redis deployments should also configure
``CACHE_REDIS_URL``. The old ``OAUTH2_CACHE_TYPE`` and
``OAUTH2_CACHE_REDIS_*`` settings are ignored; in particular, do not rename
``OAUTH2_CACHE_TYPE`` to ``RedisCache`` because that option no longer selects a
backend.

Authorization codes use namespaced, bounded-lifetime cache entries and are
consumed once. Redis consumption uses atomic ``GETDEL``. SimpleCache is suitable
for development and tests but its get/delete fallback is not atomic.

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
