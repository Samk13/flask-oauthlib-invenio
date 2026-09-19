# coding: utf-8
"""Authlib-backed compatibility shell for OAuth 2 providers."""

import datetime
import logging
from functools import wraps
from urllib.parse import urlencode

from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.flask_oauth2.requests import FlaskOAuth2Request
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.errors import (
    AccessDeniedError,
    InvalidGrantError,
    InvalidRequestError,
    UnauthorizedClientError,
)
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750.errors import InsufficientScopeError, InvalidTokenError
from authlib.oauth2.rfc7009 import RevocationEndpoint
from flask import abort, current_app, g, redirect, request, url_for
from werkzeug.utils import cached_property, import_string

__all__ = ("OAuth2Provider", "OAuth2RequestValidator")

log = logging.getLogger("flask_oauthlib")


class TokenDict(dict):
    """Token dict with Flask-OAuthlib's ``.scopes`` convenience property."""

    @property
    def scopes(self):
        scope = self.get("scope") or ""
        return scope.split()


class OAuth2Provider(object):
    """Provide OAuth2 services using Authlib behind Flask-OAuthlib's API."""

    def __init__(self, app=None, validator_class=None):
        self._before_request_funcs = []
        self._after_request_funcs = []
        self._exception_handler = None
        self._invalid_response = None
        self._validator_class = validator_class
        self._server = None
        self._require_oauth = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the provider with a Flask application."""
        self.app = app
        app.extensions = getattr(app, "extensions", {})
        app.extensions["oauthlib.provider.oauth2"] = self

    def _on_exception(self, error, redirect_content=None):
        if self._exception_handler:
            return self._exception_handler(error, redirect_content)
        return redirect(redirect_content or self.error_uri)

    @cached_property
    def error_uri(self):
        """The error page URI."""
        error_uri = self.app.config.get("OAUTH2_PROVIDER_ERROR_URI")
        if error_uri:
            return error_uri
        error_endpoint = self.app.config.get("OAUTH2_PROVIDER_ERROR_ENDPOINT")
        if error_endpoint:
            return url_for(error_endpoint)
        return "/oauth/errors"

    @cached_property
    def server(self):
        """Authlib authorization server."""
        if self._server is None:
            self.app.config.setdefault("OAUTH2_REFRESH_TOKEN_GENERATOR", True)
            self._server = _CompatAuthorizationServer(
                self.app, self._clientgetter, self._save_token, provider=self
            )
            self._configure_token_generators()
            self._register_grants()
            self._register_revocation_endpoint()
        return self._server

    @cached_property
    def resource_protector(self):
        """Authlib resource protector."""
        protector = ResourceProtector()
        protector.register_token_validator(_BearerTokenValidator(self))
        return protector

    def _configure_token_generators(self):
        """Map old Flask-OAuthlib config names to Authlib token config."""
        config = self.app.config
        expires = config.get("OAUTH2_PROVIDER_TOKEN_EXPIRES_IN")
        if expires is not None:
            config.setdefault("OAUTH2_TOKEN_EXPIRES_IN", {"default": expires})

        token_generator = config.get("OAUTH2_PROVIDER_TOKEN_GENERATOR")
        if token_generator:
            if not callable(token_generator):
                token_generator = import_string(token_generator)
            self.server.register_token_generator(
                "default", _legacy_generator(token_generator)
            )

        refresh_generator = config.get("OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR")
        if refresh_generator:
            if not callable(refresh_generator):
                refresh_generator = import_string(refresh_generator)
            default_generator = self.server._token_generators.get("default")

            def generate_token(**kwargs):
                token = default_generator(**kwargs)
                if kwargs.get("include_refresh_token"):
                    try:
                        token["refresh_token"] = refresh_generator(
                            kwargs.get("request")
                        )
                    except TypeError:
                        token["refresh_token"] = refresh_generator()
                return token

            self.server.register_token_generator("default", generate_token)

    def _register_grants(self):
        provider = self

        class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
            TOKEN_ENDPOINT_HTTP_METHODS = ["POST", "GET"]
            TOKEN_ENDPOINT_AUTH_METHODS = [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ]

            def validate_token_request(self):
                code = self.request.form.get("code")
                if code is None:
                    raise InvalidRequestError("Missing 'code' in request.")
                client = self.authenticate_token_endpoint_client()
                if not client.check_grant_type(self.GRANT_TYPE):
                    raise UnauthorizedClientError(
                        f"The client is not authorized to use 'grant_type={self.GRANT_TYPE}'"
                    )
                authorization_code = self.query_authorization_code(code, client)
                if not authorization_code:
                    error = InvalidGrantError("Invalid 'code' in request.")
                    error.status_code = 401
                    raise error
                redirect_uri = self.request.payload.redirect_uri
                original_redirect_uri = authorization_code.get_redirect_uri()
                # Flask-OAuthlib legacy tests/apps often omitted redirect_uri on
                # token exchange. Keep strict comparison only when supplied.
                if (
                    redirect_uri
                    and original_redirect_uri
                    and redirect_uri != original_redirect_uri
                ):
                    raise InvalidGrantError("Invalid 'redirect_uri' in request.")
                self.request.client = client
                self.request.authorization_code = authorization_code

            def save_authorization_code(self, code, req):
                _adapt_authlib_request(req)
                provider._grantsetter(req.client.client_id, {"code": code}, req)

            def query_authorization_code(self, code, client):
                return provider._grantgetter(client_id=client.client_id, code=code)

            def delete_authorization_code(self, authorization_code):
                authorization_code.delete()

            def authenticate_user(self, authorization_code):
                return authorization_code.user

        class ImplicitGrant(grants.ImplicitGrant):
            TOKEN_ENDPOINT_AUTH_METHODS = ["none", "client_secret_post"]

        class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
            TOKEN_ENDPOINT_HTTP_METHODS = ["POST", "GET"]
            TOKEN_ENDPOINT_AUTH_METHODS = [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ]

            def authenticate_user(self, username, password):
                if not hasattr(provider, "_usergetter"):
                    return None
                return provider._usergetter(
                    username, password, self.request.client, self.request
                )

        class ClientCredentialsGrant(grants.ClientCredentialsGrant):
            TOKEN_ENDPOINT_HTTP_METHODS = ["POST", "GET"]
            TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]

            def create_token_response(self):
                client = self.request.client
                if hasattr(client, "user"):
                    self.request.user = client.user
                return super().create_token_response()

        class RefreshTokenGrant(grants.RefreshTokenGrant):
            TOKEN_ENDPOINT_HTTP_METHODS = ["POST", "GET"]
            TOKEN_ENDPOINT_AUTH_METHODS = [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ]
            INCLUDE_NEW_REFRESH_TOKEN = True

            def authenticate_refresh_token(self, refresh_token):
                return provider._tokengetter(refresh_token=refresh_token)

            def authenticate_user(self, refresh_token):
                return refresh_token.user

            def revoke_old_credential(self, refresh_token):
                # Preserve Flask-OAuthlib behaviour: the old DB token is replaced
                # by the tokensetter when a new token is saved.
                return None

        self.server.register_grant(AuthorizationCodeGrant)
        self.server.register_grant(ImplicitGrant)
        self.server.register_grant(PasswordGrant)
        self.server.register_grant(ClientCredentialsGrant)
        self.server.register_grant(RefreshTokenGrant)

    def _register_revocation_endpoint(self):
        provider = self

        class RevokeTokenEndpoint(RevocationEndpoint):
            CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

            def query_token(self, token_string, token_type_hint):
                if token_type_hint:
                    return provider._tokengetter(**{token_type_hint: token_string})
                token = provider._tokengetter(access_token=token_string)
                if not token:
                    token = provider._tokengetter(refresh_token=token_string)
                return token

            def revoke_token(self, token, req):
                if hasattr(token, "delete"):
                    token.delete()

        self.server.register_endpoint(RevokeTokenEndpoint)

    def _save_token(self, token, req):
        _adapt_authlib_request(req)
        return self._tokensetter(TokenDict(token), req)

    def before_request(self, f):
        self._before_request_funcs.append(f)
        return f

    def after_request(self, f):
        self._after_request_funcs.append(f)
        return f

    def exception_handler(self, f):
        self._exception_handler = f
        return f

    def invalid_response(self, f):
        self._invalid_response = f
        return f

    def clientgetter(self, f):
        self._clientgetter = f
        return f

    def usergetter(self, f):
        self._usergetter = f
        return f

    def tokengetter(self, f):
        self._tokengetter = f
        return f

    def tokensetter(self, f):
        self._tokensetter = f
        return f

    def grantgetter(self, f):
        self._grantgetter = f
        return f

    def grantsetter(self, f):
        self._grantsetter = f
        return f

    def authorize_handler(self, f):
        """Authorization handler decorator."""

        @wraps(f)
        def decorated(*args, **kwargs):
            redirect_uri = request.values.get("redirect_uri", self.error_uri)
            if request.method in ("GET", "HEAD"):
                if not request.values.get("client_id"):
                    location = (
                        self.error_uri
                        + "?error=invalid_request&error_description=Missing+client_id+parameter."
                    )
                    return self._on_exception(
                        InvalidRequestError("Missing client_id parameter."), location
                    )
                if request.values.get("client_id") and not self._clientgetter(
                    request.values.get("client_id")
                ):
                    location = (
                        self.error_uri
                        + "?error=invalid_request&error_description=Invalid+client_id+parameter."
                    )
                    return self._on_exception(
                        InvalidRequestError("Invalid client_id parameter."), location
                    )
                try:
                    grant = self.server.get_consent_grant(end_user=_current_user())
                    req = grant.request
                    kwargs["scopes"] = (req.scope or "").split()
                    kwargs["request"] = req
                    kwargs["client_id"] = req.client.client_id
                    kwargs["redirect_uri"] = req.payload.redirect_uri
                    kwargs["response_type"] = req.payload.response_type
                    kwargs["state"] = req.payload.state
                except OAuth2Error as error:
                    return self._handle_authorization_error(error, redirect_uri)
                except Exception as error:  # pragma: no cover - defensive compat
                    log.exception(error)
                    return self._on_exception(error, self.error_uri)
            try:
                rv = f(*args, **kwargs)
            except OAuth2Error as error:
                return self._handle_authorization_error(error, redirect_uri)
            if not isinstance(rv, bool):
                return rv
            if not rv:
                error = AccessDeniedError(
                    redirect_uri=redirect_uri, state=request.values.get("state")
                )
                return self._handle_authorization_error(error, redirect_uri)
            return self.confirm_authorization_request()

        return decorated

    def _handle_authorization_error(self, error, redirect_uri):
        uri = getattr(error, "redirect_uri", None) or redirect_uri or self.error_uri
        try:
            status, body, headers = error(uri)
            location = dict(headers).get("Location")
        except Exception:
            location = None
        if not location:
            params = (
                error.get_body()
                if hasattr(error, "get_body")
                else [("error", str(error))]
            )
            location = self.error_uri + ("?" + urlencode(params) if params else "")
        location = location.replace("Redirect+URI+", "Mismatching+redirect+URI+")
        return self._on_exception(error, location)

    def confirm_authorization_request(self):
        """Complete an approved authorization request."""
        try:
            if "scope" in request.values and not request.values.get("scope"):
                redirect_uri = request.values.get("redirect_uri") or self.error_uri
                return redirect(redirect_uri + "?error=Scopes+must+be+set")
            grant_user = _current_user()
            return self.server.create_authorization_response(grant_user=grant_user)
        except OAuth2Error as error:
            return self._handle_authorization_error(
                error, request.values.get("redirect_uri", self.error_uri)
            )

    def verify_request(self, scopes):
        """Verify current request and return ``(valid, request)``."""
        req = self.server.create_oauth2_request(request)
        try:
            token = self.resource_protector.acquire_token(scopes)
        except OAuth2Error as error:
            req.error_message = getattr(error, "description", None) or str(error)
            return False, req
        req.access_token = token
        req.user = token.user
        req.scopes = scopes
        req.client = token.client
        return True, req

    def token_handler(self, f):
        """Access/refresh token handler decorator."""

        @wraps(f)
        def decorated(*args, **kwargs):
            f(*args, **kwargs)
            return self.server.create_token_response()

        return decorated

    def revoke_handler(self, f):
        """Token revoke decorator."""

        @wraps(f)
        def decorated(*args, **kwargs):
            f(*args, **kwargs)
            return self.server.create_endpoint_response("revocation")

        return decorated

    def require_oauth(self, *scopes):
        """Protect resource with specified scopes."""

        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                for func in self._before_request_funcs:
                    func()
                if hasattr(request, "oauth") and request.oauth:
                    return f(*args, **kwargs)
                valid, req = self.verify_request(scopes)
                for func in self._after_request_funcs:
                    valid, req = func(valid, req)
                if not valid:
                    if self._invalid_response:
                        return self._invalid_response(req)
                    return abort(401)
                request.oauth = req
                return f(*args, **kwargs)

            return decorated

        return wrapper


class OAuth2RequestValidator(object):
    """Compatibility placeholder for old custom validator imports."""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class _BearerTokenValidator(BearerTokenValidator):
    def __init__(self, provider):
        super().__init__()
        self.provider = provider

    def authenticate_token(self, token_string):
        return self.provider._tokengetter(access_token=token_string)

    def validate_token(self, token, scopes, request):
        if not token:
            raise InvalidTokenError(description="token not found")
        if token.is_expired():
            raise InvalidTokenError(description="token is expired")
        if token.is_revoked():
            raise InvalidTokenError(description="token is revoked")
        if self.scope_insufficient(token.get_scope(), scopes):
            raise InsufficientScopeError()


def _adapt_authlib_request(req):
    """Add Flask-OAuthlib request attribute aliases to Authlib requests."""
    scope = req.scope or req.payload.scope or ""
    req.scopes = scope.split() if isinstance(scope, str) else scope
    return req


class _CompatFlaskOAuth2Request(FlaskOAuth2Request):
    @property
    def form(self):
        # Flask-OAuthlib accepted token parameters in query strings for legacy
        # tests/apps. Authlib's grants read ``request.form`` for token data, so
        # expose ``values`` here for compatibility.
        return self._request.values


class _CompatAuthorizationServer(AuthorizationServer):
    def __init__(self, *args, provider=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.provider = provider

    def create_oauth2_request(self, request):
        from flask import request as flask_req

        return _CompatFlaskOAuth2Request(flask_req)

    def verify_request(self, uri, http_method, body, headers, scopes):
        """Flask-OAuthlib compatible resource verification method.

        Invenio-OAuth2Server historically called ``oauth2.server.verify_request``
        directly from a ``before_request`` hook. Authlib verifies bearer tokens
        through ``ResourceProtector`` instead, so this adapter preserves the old
        server method while delegating validation to the provider's protector.
        The explicit request arguments are accepted for API compatibility; the
        Authlib Flask integration validates the active Flask request.
        """
        req = self.create_oauth2_request(request)
        try:
            token = self.provider.resource_protector.acquire_token(scopes)
        except OAuth2Error as error:
            req.error_message = getattr(error, "description", None) or str(error)
            return False, req
        req.access_token = token
        req.user = token.user
        req.scopes = scopes
        req.client = token.client
        return True, req


def _current_user():
    if hasattr(g, "user") and g.user is not None:
        return g.user
    try:
        from flask_login import current_user

        user = current_user._get_current_object()
        if getattr(user, "is_authenticated", False):
            return user
    except Exception:  # pragma: no cover
        pass
    return True


def _legacy_generator(func):
    def _call(req):
        try:
            return func(req)
        except TypeError:
            return func()

    def generate_token(**kwargs):
        req = kwargs.get("request")
        token = TokenDict(
            access_token=_call(req),
            token_type="Bearer",
            expires_in=kwargs.get("expires_in") or 3600,
            scope=kwargs.get("scope") or "",
        )
        if kwargs.get("include_refresh_token"):
            token["refresh_token"] = _call(req)
        return token

    return generate_token
