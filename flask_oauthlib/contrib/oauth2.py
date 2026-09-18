# coding: utf-8
"""
flask_oauthlib.contrib.oauth2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SQLAlchemy and Grant-Caching for OAuth2 provider.

contributed by: Randy Topliffe
"""

import logging
from datetime import datetime, timedelta, timezone

__all__ = ("bind_cache_grant", "bind_sqlalchemy")


log = logging.getLogger("flask_oauthlib")


class Grant(object):
    """Grant is only used by `GrantCacheBinding` to store the data
    returned from the cache system.

    :param cache: Werkzeug cache instance
    :param client_id: ID of the client
    :param code: A random string
    :param redirect_uri: A URI string
    :param scopes: A space delimited list of scopes
    :param user: the authorizatopm user
    """

    def __init__(
        self,
        cache=None,
        client_id=None,
        code=None,
        redirect_uri=None,
        scopes=None,
        user=None,
    ):
        self._cache = cache
        self.client_id = client_id
        self.code = code
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.user = user
        self._key = None

    def delete(self):
        """Removes itself from the cache."""
        log.debug("Deleting grant %s for client %s" % (self.code, self.client_id))
        self._cache.delete(self.key)
        return None

    @property
    def key(self):
        """The string used as the key for the cache"""
        return self._key or "%s%s" % (self.code, self.client_id)

    @key.setter
    def key(self, value):
        self._key = value

    def __getitem__(self, item):
        return getattr(self, item)

    def keys(self):
        return ["client_id", "code", "redirect_uri", "scopes", "user"]

    def get_redirect_uri(self):
        """Return redirect URI for Authlib authorization-code grants."""
        return self.redirect_uri

    def get_scope(self):
        """Return scope string for Authlib authorization-code grants."""
        if isinstance(self.scopes, (list, tuple, set)):
            return " ".join(self.scopes)
        return self.scopes or ""


def bind_cache_grant(app, provider, current_user, config_prefix="OAUTH2"):
    """Bind authorization-code grants to Invenio-Cache.

    This keeps the historical ``bind_cache_grant`` API, but the storage
    backend is now the application's ``invenio_cache.current_cache``
    (Flask-Caching) instead of the deprecated per-OAuth ``OAUTH2_CACHE_*``
    Cachelib configuration. ``config_prefix`` is accepted for backward
    compatibility and intentionally ignored.
    """
    try:
        cache = app.extensions["invenio-cache"].cache
    except KeyError as exc:
        raise RuntimeError(
            "bind_cache_grant requires InvenioCache to be initialized on the "
            "Flask application. Configure CACHE_TYPE/CACHE_REDIS_URL via "
            "invenio-cache instead of legacy OAUTH2_CACHE_* settings."
        ) from exc

    key_prefix = app.config.get("OAUTH2_GRANT_CACHE_KEY_PREFIX", "oauth2::grant::")
    timeout = app.config.get("OAUTH2_GRANT_CACHE_EXPIRES", 100)

    def _key(client_id, code):
        return "%s%s::%s" % (key_prefix, client_id, code)

    def _consume(key):
        """Atomically consume a key when Redis supports GETDEL.

        Flask-Caching exposes the concrete backend as ``cache.cache``. Redis
        backends serialize values before storage, so direct GETDEL results must
        be passed through the backend serializer. Non-Redis backends fall back
        to get/delete, which is sufficient for development/test backends such as
        SimpleCache but is not atomic.
        """
        backend = getattr(cache, "cache", None)
        client = getattr(backend, "_write_client", None)
        if client is not None and hasattr(client, "getdel"):
            raw = client.getdel("%s%s" % (backend._get_prefix(), key))
            return backend.serializer.loads(raw)
        value = cache.get(key)
        if value is not None:
            cache.delete(key)
        return value

    @provider.grantsetter
    def create_grant(client_id, code, request, *args, **kwargs):
        """Set the grant token with the configured Invenio cache."""
        grant = Grant(
            cache,
            client_id=client_id,
            code=code["code"],
            redirect_uri=request.redirect_uri,
            scopes=request.scopes,
            user=current_user(),
        )
        grant.key = _key(client_id, grant.code)
        log.debug("Set Grant Token with key %s" % grant.key)
        cache.set(grant.key, dict(grant), timeout=timeout)

    @provider.grantgetter
    def get(client_id, code):
        """Get the grant token from the configured Invenio cache."""
        grant = Grant(cache, client_id=client_id, code=code)
        grant.key = _key(client_id, code)
        ret = _consume(grant.key)
        if not ret:
            log.debug("Grant Token not found with key %s" % grant.key)
            return None
        log.debug("Grant Token found with key %s" % grant.key)
        for k, v in ret.items():
            setattr(grant, k, v)
        return grant


def bind_sqlalchemy(
    provider, session, user=None, client=None, token=None, grant=None, current_user=None
):
    """Configures the given :class:`OAuth2Provider` instance with the
    required getters and setters for persistence with SQLAlchemy.

    An example of using all models::

        oauth = OAuth2Provider(app)

        bind_sqlalchemy(oauth, session, user=User, client=Client,
                        token=Token, grant=Grant, current_user=current_user)

    You can omit any model if you wish to register the functions yourself.
    It is also possible to override the functions by registering them
    afterwards::

        oauth = OAuth2Provider(app)

        bind_sqlalchemy(oauth, session, user=User, client=Client, token=Token)

        @oauth.grantgetter
        def get_grant(client_id, code):
            pass

        @oauth.grantsetter
        def set_grant(client_id, code, request, *args, **kwargs):
            pass

        # register tokensetter with oauth but keeping the tokengetter
        # registered by `SQLAlchemyBinding`
        # You would only do this for the token and grant since user and client
        # only have getters
        @oauth.tokensetter
        def set_token(token, request, *args, **kwargs):
            pass

    Note that current_user is only required if you're using SQLAlchemy
    for grant caching. If you're using another caching system with
    GrantCacheBinding instead, omit current_user.

    :param provider: :class:`OAuth2Provider` instance
    :param session: A :class:`Session` object
    :param user: :class:`User` model
    :param client: :class:`Client` model
    :param token: :class:`Token` model
    :param grant: :class:`Grant` model
    :param current_user: function that returns a :class:`User` object
    """
    if user:
        user_binding = UserBinding(user, session)
        provider.usergetter(user_binding.get)

    if client:
        client_binding = ClientBinding(client, session)
        provider.clientgetter(client_binding.get)

    if token:
        token_binding = TokenBinding(token, session, current_user)
        provider.tokengetter(token_binding.get)
        provider.tokensetter(token_binding.set)

    if grant:
        if not current_user:
            raise ValueError(("`current_user` is required" "for Grant Binding"))
        grant_binding = GrantBinding(grant, session, current_user)
        provider.grantgetter(grant_binding.get)
        provider.grantsetter(grant_binding.set)


class BaseBinding(object):
    """Base Binding

    :param model: SQLAlchemy Model class
    :param session: A :class:`Session` object
    """

    def __init__(self, model, session):
        self.session = session
        self.model = model

    @property
    def query(self):
        """Determines which method of getting the query object for use"""
        if hasattr(self.model, "query"):
            return self.model.query
        else:
            return self.session.query(self.model)


class UserBinding(BaseBinding):
    """Object use by SQLAlchemyBinding to register the user getter"""

    def get(self, username, password, *args, **kwargs):
        """Returns the User object

        Returns None if the user isn't found or the passwords don't match

        :param username: username of the user
        :param password: password of the user
        """
        user = self.query.filter_by(username=username).first()
        if user and user.check_password(password):
            return user
        return None


class ClientBinding(BaseBinding):
    """Object use by SQLAlchemyBinding to register the client getter"""

    def get(self, client_id):
        """Returns a Client object with the given client ID

        :param client_id: ID if the client
        """
        return self.query.filter_by(client_id=client_id).first()


class TokenBinding(BaseBinding):
    """Object use by SQLAlchemyBinding to register the token
    getter and setter
    """

    def __init__(self, model, session, current_user=None):
        self.current_user = current_user
        super(TokenBinding, self).__init__(model, session)

    def get(self, access_token=None, refresh_token=None):
        """returns a Token object with the given access token or refresh token

        :param access_token: User's access token
        :param refresh_token: User's refresh token
        """
        if access_token:
            return self.query.filter_by(access_token=access_token).first()
        elif refresh_token:
            return self.query.filter_by(refresh_token=refresh_token).first()
        return None

    def set(self, token, request, *args, **kwargs):
        """Creates a Token object and removes all expired tokens that belong
        to the user

        :param token: token object
        :param request: OAuthlib request object
        """
        if hasattr(request, "user") and request.user:
            user = request.user
        elif self.current_user:
            # for implicit token
            user = self.current_user()

        client = request.client

        tokens = self.query.filter_by(client_id=client.client_id, user_id=user.id).all()
        if tokens:
            for tk in tokens:
                self.session.delete(tk)
            self.session.commit()

        expires_in = token.get("expires_in")
        expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        tok = self.model(**token)
        tok.expires = expires
        tok.client_id = client.client_id
        tok.user_id = user.id

        self.session.add(tok)
        self.session.commit()
        return tok


class GrantBinding(BaseBinding):
    """Object use by SQLAlchemyBinding to register the grant
    getter and setter
    """

    def __init__(self, model, session, current_user):
        self.current_user = current_user
        super(GrantBinding, self).__init__(model, session)

    def set(self, client_id, code, request, *args, **kwargs):
        """Creates Grant object with the given params

        :param client_id: ID of the client
        :param code:
        :param request: OAuthlib request object
        """
        expires = datetime.now(timezone.utc) + timedelta(seconds=100)
        grant = self.model(
            client_id=request.client.client_id,
            code=code["code"],
            redirect_uri=request.redirect_uri,
            scope=" ".join(request.scopes),
            user=self.current_user(),
            expires=expires,
        )
        self.session.add(grant)

        self.session.commit()

    def get(self, client_id, code):
        """Get the Grant object with the given client ID and code

        :param client_id: ID of the client
        :param code:
        """
        return self.query.filter_by(client_id=client_id, code=code).first()
