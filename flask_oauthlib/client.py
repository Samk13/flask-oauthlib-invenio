# coding: utf-8
"""Authlib-backed compatibility shell for :mod:`flask_oauthlib.client`.

The public API intentionally mirrors Flask-OAuthlib enough for Invenio and
instance-defined remote providers while delegating OAuth protocol handling to
Authlib.
"""

import logging
from copy import copy
from functools import wraps
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

try:
    import urllib2 as http
except ImportError:  # pragma: no cover
    from urllib import request as http

from authlib.integrations.base_client import MismatchingStateError, OAuthError
from authlib.integrations.flask_client import OAuth as AuthlibOAuth
from authlib.oauth1 import SIGNATURE_HMAC_SHA1, ClientAuth
from flask import current_app, json, redirect, request, session
from werkzeug.datastructures import MultiDict
from werkzeug.http import parse_options_header
from werkzeug.utils import cached_property

from .utils import to_bytes

log = logging.getLogger("flask_oauthlib")

__all__ = ("OAuth", "OAuthRemoteApp", "OAuthResponse", "OAuthException")


class OAuth(object):
    """Registry for remote applications."""

    state_key = "oauthlib.client"

    def __init__(self, app=None):
        self.remote_apps = {}
        self._authlib = AuthlibOAuth()
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Init app with Flask instance."""
        self.app = app
        app.extensions = getattr(app, "extensions", {})
        app.extensions[self.state_key] = self
        self._authlib.init_app(app)

    def remote_app(self, name, register=True, **kwargs):
        """Registers a new remote application."""
        remote = OAuthRemoteApp(self, name, **kwargs)
        if register:
            assert name not in self.remote_apps
            self.remote_apps[name] = remote
        return remote

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            app = self.remote_apps.get(key)
            if app:
                return app
            raise AttributeError("No such app: %s" % key)


_etree = None


def get_etree():
    """Load XML parser lazily."""
    global _etree
    if _etree is not None:
        return _etree
    try:
        from lxml import etree as _etree
    except ImportError:
        try:
            from xml.etree import cElementTree as _etree
        except ImportError:
            from xml.etree import ElementTree as _etree
    return _etree


def parse_response(resp, content, strict=False, content_type=None):
    """Parse HTTP response content with legacy Flask-OAuthlib semantics."""
    if not content_type:
        content_type = resp.headers.get("content-type", "application/json")
    ct, options = parse_options_header(content_type)

    if ct in ("application/json", "text/javascript"):
        if not content:
            return {}
        if isinstance(content, bytes):
            content = content.decode(options.get("charset", "utf-8"))
        return json.loads(content)

    if ct in ("application/xml", "text/xml"):
        return get_etree().fromstring(content)

    if ct != "application/x-www-form-urlencoded" and strict:
        return content

    charset = options.get("charset", "utf-8")
    if isinstance(content, bytes):
        content = content.decode(charset)
    parsed = urlparse(content)
    return MultiDict(
        parse_qsl(
            parsed.path, encoding=charset, strict_parsing=strict, keep_blank_values=True
        )
    )


def prepare_request(uri, headers=None, data=None, method=None):
    """Make request parameters right."""
    if headers is None:
        headers = {}

    if data and not method:
        method = "POST"
    elif not method:
        method = "GET"

    if method == "GET" and data:
        uri += ("&" if "?" in uri else "?") + urlencode(data)
        data = None

    return uri, headers, data, method


def encode_request_data(data, format):
    """Encode request data."""
    if format is None:
        return data, None
    if format == "json":
        return json.dumps(data or {}), "application/json"
    if format == "urlencoded":
        return urlencode(data or {}), "application/x-www-form-urlencoded"
    raise TypeError("Unknown format %r" % format)


class OAuthResponse(object):
    """Legacy response wrapper."""

    def __init__(self, resp, content=None, content_type=None):
        self._resp = resp
        if content is None:
            content = getattr(resp, "content", b"")
        self.raw_data = content
        self.data = parse_response(
            resp, content, strict=True, content_type=content_type
        )

    @property
    def status(self):
        """The status code of the response."""
        return getattr(self._resp, "status_code", getattr(self._resp, "code", None))


class OAuthException(RuntimeError):
    """Legacy OAuth exception."""

    def __init__(self, message, type=None, data=None):
        self.message = message
        self.type = type
        self.data = data

    def __str__(self):
        return self.message


class OAuthRemoteApp(object):
    """Represents a remote OAuth application."""

    def __init__(
        self,
        oauth,
        name,
        base_url=None,
        request_token_url=None,
        access_token_url=None,
        authorize_url=None,
        consumer_key=None,
        consumer_secret=None,
        rsa_key=None,
        signature_method=None,
        request_token_params=None,
        request_token_method=None,
        access_token_params=None,
        access_token_method=None,
        access_token_headers=None,
        content_type=None,
        app_key=None,
        encoding="utf-8",
    ):
        self.oauth = oauth
        self.name = name
        self._base_url = base_url
        self._request_token_url = request_token_url
        self._access_token_url = access_token_url
        self._authorize_url = authorize_url
        self._consumer_key = consumer_key
        self._consumer_secret = consumer_secret
        self._rsa_key = rsa_key
        self._signature_method = signature_method
        self._request_token_params = request_token_params
        self._request_token_method = request_token_method
        self._access_token_params = access_token_params
        self._access_token_method = access_token_method
        self._access_token_headers = access_token_headers or {}
        self._content_type = content_type
        self._tokengetter = None
        self._authlib_client = None
        self.app_key = app_key
        self.encoding = encoding

        if not app_key and not consumer_key:
            raise TypeError("OAuthRemoteApp requires consumer key")

    @cached_property
    def base_url(self):
        return self._get_property("base_url", "")

    @cached_property
    def request_token_url(self):
        return self._get_property("request_token_url", None)

    @cached_property
    def access_token_url(self):
        return self._get_property("access_token_url")

    @cached_property
    def authorize_url(self):
        return self._get_property("authorize_url")

    @cached_property
    def consumer_key(self):
        return self._get_property("consumer_key")

    @cached_property
    def consumer_secret(self):
        return self._get_property("consumer_secret")

    @cached_property
    def rsa_key(self):
        return self._get_property("rsa_key", None)

    @cached_property
    def signature_method(self):
        return self._get_property("signature_method", None)

    @cached_property
    def request_token_params(self):
        return self._get_property("request_token_params", {})

    @cached_property
    def request_token_method(self):
        return self._get_property("request_token_method", "GET")

    @cached_property
    def access_token_params(self):
        return self._get_property("access_token_params", {})

    @cached_property
    def access_token_method(self):
        return self._get_property("access_token_method", "POST")

    @cached_property
    def content_type(self):
        return self._get_property("content_type", None)

    def _get_property(self, key, default=False):
        attr = getattr(self, "_%s" % key)
        if attr is not None:
            return attr
        if not self.app_key:
            if default is not False:
                return default
            return attr
        app = self.oauth.app or current_app
        if self.app_key in app.config:
            config = app.config[self.app_key]
            if default is not False:
                return config.get(key, default)
            return config[key]
        config_key = "%s_%s" % (self.app_key, key.upper())
        if default is not False:
            return app.config.get(config_key, default)
        return app.config[config_key]

    def _client_kwargs(self):
        kwargs = {}
        params = dict(self.request_token_params or {})
        scope = params.pop("scope", None)
        if scope:
            kwargs["scope"] = scope
        realm = params.pop("realm", None)
        if realm and self.request_token_url:
            kwargs["realm"] = realm
        if not self.request_token_url:
            kwargs.setdefault("token_endpoint_auth_method", "client_secret_post")
        return kwargs

    def _register_authlib_client(self):
        oauth = self.oauth._authlib
        register_kwargs = dict(
            client_id=self.consumer_key,
            client_secret=self.consumer_secret,
            request_token_url=self.request_token_url,
            access_token_url=self.expand_url(self.access_token_url),
            authorize_url=self.expand_url(self.authorize_url),
            api_base_url=self.base_url,
            request_token_params={
                k: v
                for k, v in (self.request_token_params or {}).items()
                if k != "realm"
            },
            access_token_params=self.access_token_params,
            client_kwargs=self._client_kwargs(),
            fetch_token=lambda: self.get_request_token(),
        )
        oauth.register(self.name, overwrite=True, **register_kwargs)
        return oauth.create_client(self.name)

    @property
    def authlib_client(self):
        """Underlying Authlib client."""
        if self._authlib_client is None:
            self._authlib_client = self._register_authlib_client()
        return self._authlib_client

    def make_client(self, token=None):
        """Return Authlib client with optional token assigned."""
        if self.oauth.app is None:

            class _Client(object):
                pass

            client = _Client()
            client.token = self._normalize_token(token)
            return client
        client = self.authlib_client
        if token is not None:
            client.token = self._normalize_token(token)
        return client

    @staticmethod
    def http_request(uri, headers=None, data=None, method=None):
        """Low-level HTTP request helper kept for compatibility."""
        uri, headers, data, method = prepare_request(uri, headers, data, method)
        req = http.Request(uri, headers=headers, data=data)
        req.get_method = lambda: method.upper()
        try:
            resp = http.urlopen(req)
            content = resp.read()
            resp.close()
            return resp, content
        except http.HTTPError as resp:
            content = resp.read()
            resp.close()
            return resp, content

    def get(self, *args, **kwargs):
        kwargs["method"] = "GET"
        return self.request(*args, **kwargs)

    def post(self, *args, **kwargs):
        kwargs["method"] = "POST"
        return self.request(*args, **kwargs)

    def put(self, *args, **kwargs):
        kwargs["method"] = "PUT"
        return self.request(*args, **kwargs)

    def delete(self, *args, **kwargs):
        kwargs["method"] = "DELETE"
        return self.request(*args, **kwargs)

    def patch(self, *args, **kwargs):
        kwargs["method"] = "PATCH"
        return self.request(*args, **kwargs)

    def pre_request(self, uri, headers, data):
        """Hook for custom providers to adjust outgoing requests."""
        return uri, headers, data

    def request(
        self,
        url,
        data=None,
        headers=None,
        format="urlencoded",
        method="GET",
        content_type=None,
        token=None,
    ):
        """Send a request to the remote server with OAuth tokens attached."""
        kwargs = {"headers": dict(headers or {})}
        if method == "GET":
            kwargs["params"] = data
        else:
            if content_type is None:
                if format == "json":
                    kwargs["json"] = data or {}
                else:
                    kwargs["data"] = data or {}
            else:
                kwargs["data"] = data
                kwargs["headers"]["Content-Type"] = content_type
        authlib_token = self._normalize_token(token) if token is not None else None
        # Preserve Flask-OAuthlib's overridable ``http_request`` hook. Many
        # tests and custom providers monkeypatch it to route requests through a
        # Flask test client rather than the network.
        if authlib_token is None:
            authlib_token = self.get_request_token()
        data = kwargs.get("params") if method == "GET" else kwargs.get("data")
        if "json" in kwargs:
            data, content_type = encode_request_data(kwargs["json"], "json")
            kwargs["headers"]["Content-Type"] = content_type
        uri = self.expand_url(url)
        if self.request_token_url:
            auth = self._oauth1_auth(
                token=authlib_token.get("oauth_token"),
                token_secret=authlib_token.get("oauth_token_secret"),
            )
            uri, signed_headers, signed_body = auth.prepare(
                method,
                uri,
                kwargs["headers"],
                to_bytes(data, self.encoding) if isinstance(data, str) else data,
            )
            kwargs["headers"] = signed_headers
            data = signed_body
        else:
            access_token = authlib_token.get("access_token") or authlib_token.get(
                "oauth_token"
            )
            if access_token:
                kwargs["headers"].setdefault(
                    "Authorization", "Bearer %s" % access_token
                )
        uri, headers, data = self.pre_request(uri, kwargs["headers"], data)
        resp, content = self.http_request(
            uri,
            headers,
            data=data,
            method=method,
        )
        return OAuthResponse(resp, content, self.content_type)

    def _oauth1_auth(self, token=None, token_secret=None, verifier=None, callback=None):
        return ClientAuth(
            self.consumer_key,
            client_secret=self.consumer_secret,
            token=token,
            token_secret=token_secret,
            redirect_uri=callback,
            rsa_key=self.rsa_key,
            verifier=verifier,
            signature_method=self.signature_method or SIGNATURE_HMAC_SHA1,
            realm=(self.request_token_params or {}).get("realm"),
        )

    def _fetch_oauth1_request_token(self, callback):
        auth = self._oauth1_auth(callback=callback)
        uri, headers, body = auth.prepare(
            self.request_token_method or "GET",
            self.expand_url(self.request_token_url),
            {},
            None,
        )
        resp, content = self.http_request(uri, headers, body, self.request_token_method)
        data = parse_response(
            resp, content, content_type="application/x-www-form-urlencoded"
        )
        if "oauth_token" not in data:
            raise OAuthException("Failed to generate request token", data=data)
        session["%s_oauth_request_token" % self.name] = dict(data)
        return data

    def authorize(self, callback=None, state=None, **kwargs):
        """Redirect to remote authorization URL."""
        params = dict(self.request_token_params or {})
        params.update(kwargs)
        if callable(state):
            state = state()
        if state is not None:
            params["state"] = state
        session["%s_oauthredir" % self.name] = callback
        if self.request_token_url:
            token = self._fetch_oauth1_request_token(callback)
            url = self.expand_url(self.authorize_url)
            return redirect(
                url
                + ("&" if "?" in url else "?")
                + urlencode({"oauth_token": token["oauth_token"]})
            )
        try:
            return self.authlib_client.authorize_redirect(callback, **params)
        except OAuthError as exc:
            raise OAuthException(str(exc), type=getattr(exc, "error", None)) from exc

    def tokengetter(self, f):
        """Register a function as token getter."""
        self._tokengetter = f
        self._authlib_client = None
        return f

    def expand_url(self, url):
        return urljoin(self.base_url, url)

    def get_request_token(self):
        if self._tokengetter is None:
            raise OAuthException("missing tokengetter", type="token_missing")
        rv = self._tokengetter()
        if rv is None:
            raise OAuthException("No token available", type="token_missing")
        return self._normalize_token(rv)

    def _normalize_token(self, token):
        if token is None:
            return None
        if isinstance(token, (tuple, list)):
            if self.request_token_url:
                return {"oauth_token": token[0], "oauth_token_secret": token[1]}
            return {"access_token": token[0]}
        if isinstance(token, str):
            return {"access_token": token}
        return token

    def authorized_response(self, args=None):
        """Handle authorization response and return token data."""
        if self.request_token_url:
            args = args or request.args
            if args.get("error"):
                return None
            request_token = session.get("%s_oauth_request_token" % self.name) or {}
            oauth_token = args.get("oauth_token")
            verifier = args.get("oauth_verifier")
            if not oauth_token or not verifier:
                return None
            if oauth_token != request_token.get("oauth_token"):
                raise OAuthException(
                    "Mismatching OAuth request token", type="token_mismatch"
                )
            session.pop("%s_oauth_request_token" % self.name, None)
            auth = self._oauth1_auth(
                token=oauth_token,
                token_secret=request_token.get("oauth_token_secret"),
                verifier=verifier,
            )
            uri, headers, body = auth.prepare(
                self.access_token_method or "GET",
                self.expand_url(self.access_token_url),
                {},
                None,
            )
            resp, content = self.http_request(
                uri, headers, body, self.access_token_method
            )
            data = parse_response(
                resp, content, content_type="application/x-www-form-urlencoded"
            )
            if "oauth_token" not in data:
                raise OAuthException("Failed to fetch access token", data=data)
            return data
        if request.args.get("error"):
            return None
        client = self.authlib_client
        state = request.args.get("state")
        state_data = client.framework.get_state_data(session, state) if state else None
        if not state_data:
            # Missing, mismatched and replayed state all fail before any token
            # request is made.
            exc = MismatchingStateError()
            raise OAuthException(str(exc), type="mismatching_state") from exc
        client.framework.clear_state_data(session, state)

        token = self.handle_oauth2_response(request.args, state_data=state_data)
        if token and "id_token" in token and state_data.get("nonce"):
            token["userinfo"] = client.parse_id_token(token, nonce=state_data["nonce"])
        client.token = token
        return token

    def handle_oauth2_response(self, args, state_data=None):
        """Legacy OAuth2 code exchange using the overridable HTTP hook."""
        code = args.get("code")
        if not code:
            return None
        remote_args = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.consumer_key,
            "client_secret": self.consumer_secret,
            "redirect_uri": (state_data or {}).get("redirect_uri")
            or session.get("%s_oauthredir" % self.name),
            "code_verifier": (state_data or {}).get("code_verifier"),
        }
        remote_args.update(self.access_token_params)
        remote_args = {k: v for k, v in remote_args.items() if v is not None}
        headers = copy(self._access_token_headers)
        if self.access_token_method == "GET":
            url = self.expand_url(self.access_token_url)
            url += ("&" if "?" in url else "?") + urlencode(remote_args)
            resp, content = self.http_request(url, headers=headers, method="GET")
        else:
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            body = urlencode(remote_args)
            resp, content = self.http_request(
                self.expand_url(self.access_token_url),
                headers=headers,
                data=to_bytes(body, self.encoding),
                method=self.access_token_method,
            )
        data = parse_response(resp, content, content_type=self.content_type)
        if getattr(resp, "code", getattr(resp, "status_code", None)) not in (200, 201):
            raise OAuthException(
                "Invalid response from %s" % self.name,
                type="invalid_response",
                data=data,
            )
        return data

    def authorized_handler(self, f):
        """Deprecated callback decorator kept for compatibility."""

        @wraps(f)
        def decorated(*args, **kwargs):
            data = self.authorized_response()
            return f(*((data,) + args), **kwargs)

        return decorated
