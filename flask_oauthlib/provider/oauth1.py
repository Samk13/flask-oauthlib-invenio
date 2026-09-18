# coding: utf-8
"""OAuth1 provider compatibility adapter backed by Authlib."""

import functools
from types import SimpleNamespace
from urllib.parse import urlencode

from authlib.integrations.flask_oauth1 import AuthorizationServer, ResourceProtector
from authlib.oauth1.rfc5849 import TemporaryCredential
from authlib.oauth1.rfc5849.errors import InvalidRequestError, OAuth1Error
from flask import Response, redirect, request

__all__ = ("OAuth1Provider", "OAuth1RequestValidator")


class _ClientAdapter:
    def __init__(self, client):
        self._client = client

    def __getattr__(self, name):
        return getattr(self._client, name)

    def get_client_secret(self):
        return self._client.client_secret

    def get_default_redirect_uri(self):
        return self._client.default_redirect_uri

    def get_rsa_public_key(self):
        return getattr(self._client, "rsa_key", None)


class _CredentialAdapter:
    def __init__(self, credential):
        self._credential = credential

    def __getattr__(self, name):
        return getattr(self._credential, name)

    def get_client_id(self):
        return self._credential.client_key

    def get_redirect_uri(self):
        return self._credential.redirect_uri

    def check_verifier(self, verifier):
        return self._credential.verifier == verifier

    def get_oauth_token(self):
        return self._credential.token

    def get_oauth_token_secret(self):
        return self._credential.secret

    @property
    def realms(self):
        return getattr(self._credential, "realms", [])


class _OAuth1RequestAdapter:
    """Legacy request object passed to setter callbacks."""

    def __init__(self, oauth_request, provider):
        self._request = oauth_request
        self.client = provider._clientgetter(oauth_request.client_id)
        self.client_key = oauth_request.client_id
        self.redirect_uri = oauth_request.redirect_uri
        self.realms = provider._parse_realms(oauth_request.realm)
        self.user = getattr(oauth_request, "user", None)

    def __getattr__(self, name):
        return getattr(self._request, name)


class _OAuth1AuthorizationServer(AuthorizationServer):
    """Authlib server with legacy Flask-OAuthlib extension points."""

    TEMPORARY_CREDENTIALS_METHOD = "GET"

    def __init__(self, provider):
        self.provider = provider
        super().__init__(query_client=provider._query_client)

    def exists_nonce(self, nonce, oauth_request):
        return self.provider._exists_nonce(
            nonce, oauth_request.timestamp, oauth_request.client_id, oauth_request.token
        )

    def validate_temporary_credentials_request(self, oauth_request):
        # Flask-OAuthlib accepted GET in these tests and older integrations.
        old_method = oauth_request.method
        oauth_request.method = self.TEMPORARY_CREDENTIALS_METHOD
        try:
            rv = super().validate_temporary_credentials_request(oauth_request)
        finally:
            oauth_request.method = old_method

        self.provider._validate_realms(oauth_request.client, oauth_request.realm)
        return rv

    def create_temporary_credential(self, oauth_request):
        token = self.token_generator()
        legacy_request = _OAuth1RequestAdapter(oauth_request, self.provider)
        grant = self.provider._grantsetter(token, legacy_request)
        if grant is not None:
            return _CredentialAdapter(grant)
        return TemporaryCredential(
            oauth_token=token["oauth_token"],
            oauth_token_secret=token["oauth_token_secret"],
            client_id=oauth_request.client_id,
            oauth_callback=oauth_request.redirect_uri,
        )

    def get_temporary_credential(self, oauth_request):
        grant = self.provider._grantgetter(oauth_request.token)
        return _CredentialAdapter(grant) if grant else None

    def delete_temporary_credential(self, oauth_request):
        grant = self.provider._grantgetter(oauth_request.token)
        if grant and hasattr(grant, "delete"):
            grant.delete()

    def create_authorization_verifier(self, oauth_request):
        verifier = self.token_generator()["oauth_token"]
        legacy_request = _OAuth1RequestAdapter(oauth_request, self.provider)
        legacy_request.user = oauth_request.user
        self.provider._verifiersetter(oauth_request.token, {"oauth_verifier": verifier})
        return verifier

    def create_token_credential(self, oauth_request):
        token = self.token_generator()
        legacy_request = _OAuth1RequestAdapter(oauth_request, self.provider)
        legacy_request.client = self.provider._clientgetter(oauth_request.client_id)
        legacy_request.user = getattr(oauth_request.credential, "user", None)
        if legacy_request.user is None and hasattr(oauth_request.credential, "user_id"):
            # Keep the old request shape useful for SQLAlchemy fixtures.
            legacy_request.user = getattr(oauth_request.credential, "user", None)
        token["oauth_authorized_realms"] = " ".join(oauth_request.credential.realms)
        self.provider._tokensetter(token, legacy_request)
        return TemporaryCredential(
            oauth_token=token["oauth_token"],
            oauth_token_secret=token["oauth_token_secret"],
        )


class _OAuth1ResourceProtector(ResourceProtector):
    def __init__(self, provider):
        self.provider = provider
        super().__init__(
            query_client=provider._query_client,
            query_token=provider._query_token,
            exists_nonce=provider._exists_nonce,
        )

    def acquire_credential(self):
        credential = super().acquire_credential()
        return credential


class OAuth1Provider(object):
    """Flask-OAuthlib compatible OAuth1 provider using Authlib."""

    def __init__(self, app=None):
        self.app = None
        self._clientgetter = None
        self._tokengetter = None
        self._tokensetter = None
        self._grantgetter = None
        self._grantsetter = None
        self._verifiergetter = None
        self._verifiersetter = None
        self._noncegetter = None
        self._noncesetter = None
        self.server = _OAuth1AuthorizationServer(self)
        self.protector = _OAuth1ResourceProtector(self)
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.server.init_app(app)
        self.protector.init_app(app)
        app.extensions = getattr(app, "extensions", {})
        app.extensions["oauthlib.provider.oauth1"] = self

    def clientgetter(self, f):
        self._clientgetter = f
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

    def verifiergetter(self, f):
        self._verifiergetter = f
        return f

    def verifiersetter(self, f):
        self._verifiersetter = f
        return f

    def noncegetter(self, f):
        self._noncegetter = f
        return f

    def noncesetter(self, f):
        self._noncesetter = f
        return f

    def _query_client(self, client_key):
        client = self._clientgetter(client_key) if self._clientgetter else None
        return _ClientAdapter(client) if client else None

    def _query_token(self, client_key, token):
        token_obj = self._tokengetter(client_key, token) if self._tokengetter else None
        return _CredentialAdapter(token_obj) if token_obj else None

    def _exists_nonce(self, nonce, timestamp, client_key, token):
        exists = False
        if self._noncegetter:
            exists = bool(self._noncegetter(nonce, timestamp, client_key, token))
        if not exists and self._noncesetter:
            self._noncesetter(nonce, timestamp, client_key, token)
        return exists

    def _parse_realms(self, realm):
        if not realm:
            return []
        if isinstance(realm, str):
            return [item for item in realm.split() if item]
        return list(realm)

    def _validate_realms(self, client, realm):
        requested = self._parse_realms(realm)
        if not requested:
            return
        allowed = set(getattr(client, "default_realms", []) or [])
        if not allowed.issuperset(requested):
            raise InvalidRequestError('Invalid "realm" value')

    def _error_response(self, error):
        if isinstance(error, OAuth1Error):
            body = urlencode(error.get_body())
            status = error.status_code
            headers = error.get_headers()
        else:
            body = urlencode({"error": str(error)})
            status = 400
            headers = [("Content-Type", "application/x-www-form-urlencoded")]
        return Response(body, status=status, headers=headers)

    def request_token_handler(self, f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            f(*args, **kwargs)
            return self.server.create_temporary_credentials_response(request)

        return decorated

    def access_token_handler(self, f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            f(*args, **kwargs)
            return self.server.create_token_response(request)

        return decorated

    @property
    def authorize_handler(self):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    oauth_request = self.server.check_authorization_request()
                except OAuth1Error as error:
                    return redirect("/oauth/errors?" + urlencode(error.get_body()))

                if request.method == "GET":
                    return f(*args, **kwargs)

                confirmed = f(*args, **kwargs)
                if not confirmed:
                    redirect_uri = oauth_request.credential.get_redirect_uri()
                    return redirect(
                        redirect_uri
                        + ("&" if "?" in redirect_uri else "?")
                        + urlencode({"error": "denied"})
                    )
                grant_user = getattr(request, "user", None)
                from flask import g

                grant_user = getattr(g, "user", grant_user)
                return self.server.create_authorization_response(
                    request, grant_user=grant_user
                )

            return decorated

        return wrapper

    def require_oauth(self, realm=None):
        realms = self._parse_realms(realm)

        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    credential = self.protector.acquire_credential()
                except OAuth1Error as error:
                    return self._error_response(error)

                token_realms = set(getattr(credential, "realms", []) or [])
                if realms and not token_realms.issuperset(realms):
                    response = self._error_response(
                        InvalidRequestError('Invalid "realm" value')
                    )
                    response.status_code = 401
                    return response

                request.oauth = SimpleNamespace(
                    client=getattr(credential, "client", None),
                    user=getattr(credential, "user", None),
                    token=credential,
                    realms=list(token_realms),
                )
                return f(*args, **kwargs)

            return decorated

        return wrapper


class OAuth1RequestValidator(object):
    """Compatibility placeholder for old OAuth1 validator imports."""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
