# coding: utf-8

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from authlib.oauth2.rfc7636 import create_s256_code_challenge

from .._base import to_base64
from .base import (
    Client,
    Grant,
    TestCase,
    User,
    cache_provider,
    create_server,
    db,
    default_provider,
    sqlalchemy_provider,
)


class TestDefaultProvider(TestCase):
    def create_server(self):
        create_server(self.app)

    def prepare_data(self):
        self.create_server()

        oauth_client = Client(
            name="ios",
            client_id="code-client",
            client_secret="code-secret",
            _redirect_uris="http://localhost/authorized",
        )

        db.session.add(User(username="foo"))
        db.session.add(oauth_client)
        db.session.commit()

        self.oauth_client = oauth_client
        self.authorize_url = (
            "/oauth/authorize?response_type=code&client_id=%s"
        ) % oauth_client.client_id

    def test_get_authorize(self):
        rv = self.client.get("/oauth/authorize")
        assert "client_id" in rv.location

        rv = self.client.get("/oauth/authorize?client_id=no")
        assert "client_id" in rv.location

        url = "/oauth/authorize?client_id=%s" % self.oauth_client.client_id
        rv = self.client.get(url)
        assert "error" in rv.location

        rv = self.client.get(self.authorize_url)
        assert b"confirm" in rv.data

    def test_post_authorize(self):
        url = self.authorize_url + "&scope=foo"
        rv = self.client.post(url, data={"confirm": "yes"})
        assert "invalid_scope" in rv.location

        url = self.authorize_url + "&scope=email"
        self.client.get(url)
        rv = self.client.post(url, data={"confirm": "yes"})
        assert "code" in rv.location

        url = self.authorize_url + "&scope="
        self.client.get(url)
        rv = self.client.post(url, data={"confirm": "yes"})
        assert rv.location.startswith("http://localhost/authorized?")

    def test_direct_post_cannot_redirect_to_unregistered_uri(self):
        url = (
            self.authorize_url
            + "&scope=&redirect_uri=https://attacker.example/callback"
        )
        rv = self.client.post(url, data={"confirm": "yes"})

        assert rv.location.startswith("/oauth/errors")

    def test_consent_is_bound_to_validated_state(self):
        url = self.authorize_url + "&scope=email&state=expected"
        self.client.get(url)

        rv = self.client.post(
            self.authorize_url + "&scope=email&state=tampered",
            data={"confirm": "yes"},
        )

        assert rv.location.startswith("/oauth/errors")
        assert "code=" not in rv.location

    def test_invalid_token(self):
        rv = self.client.get("/oauth/token")
        assert b"unsupported_grant_type" in rv.data

        rv = self.client.get("/oauth/token?grant_type=authorization_code")
        assert b"error" in rv.data
        assert b"code" in rv.data

        url = (
            "/oauth/token?grant_type=authorization_code" "&code=nothing&client_id=%s"
        ) % self.oauth_client.client_id
        rv = self.client.get(url)
        assert b"invalid_client" in rv.data

        url += "&client_secret=" + self.oauth_client.client_secret
        rv = self.client.get(url)
        assert b"invalid_client" not in rv.data
        assert rv.status_code == 401

    def test_invalid_redirect_uri(self):
        authorize_url = (
            "/oauth/authorize?response_type=code&client_id=code-client"
            "&redirect_uri=http://localhost:8000/authorized"
            "&scope=invalid"
        )
        rv = self.client.get(authorize_url)
        assert "error=" in rv.location
        assert "Mismatching+redirect+URI" in rv.location

    def test_get_token(self):
        expires = datetime.now(timezone.utc) + timedelta(seconds=100)
        grant = Grant(
            user_id=1,
            client_id=self.oauth_client.client_id,
            scope="email",
            redirect_uri="http://localhost/authorized",
            code="test-get-token",
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

        url = (
            "/oauth/token?grant_type=authorization_code&code=test-get-token"
            "&redirect_uri=http%3A%2F%2Flocalhost%2Fauthorized"
        )
        rv = self.client.get(url + "&client_id=%s" % (self.oauth_client.client_id))
        assert b"invalid_client" in rv.data

        rv = self.client.get(
            url
            + "&client_id=%s&client_secret=%s"
            % (self.oauth_client.client_id, self.oauth_client.client_secret)
        )
        assert b"access_token" in rv.data

        grant = Grant(
            user_id=1,
            client_id=self.oauth_client.client_id,
            scope="email",
            redirect_uri="http://localhost/authorized",
            code="test-get-token",
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

        rv = self.client.get(
            url,
            headers={
                "authorization": "Basic "
                + to_base64(
                    "%s:%s"
                    % (self.oauth_client.client_id, self.oauth_client.client_secret)
                )
            },
        )
        assert b"access_token" in rv.data


class TestSQLAlchemyProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, sqlalchemy_provider(self.app))


class TestCacheProvider(TestDefaultProvider):
    def create_server(self):
        create_server(self.app, cache_provider(self.app))

    def issue_pkce_code(self, verifier):
        challenge = create_s256_code_challenge(verifier)
        url = (
            self.authorize_url
            + "&scope=email&code_challenge="
            + challenge
            + "&code_challenge_method=S256"
        )
        self.client.get(url)
        rv = self.client.post(url, data={"confirm": "yes"})
        code = parse_qs(urlparse(rv.location).query)["code"][0]
        cached = self.app.extensions["invenio-cache"].cache.get(
            "oauth2::grant::%s::%s" % (self.oauth_client.client_id, code)
        )
        assert cached["code_challenge"] == challenge
        return code

    def exchange_pkce_code(self, code, verifier=None):
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.oauth_client.client_id,
            "client_secret": self.oauth_client.client_secret,
            "redirect_uri": "http://localhost/authorized",
        }
        if verifier is not None:
            data["code_verifier"] = verifier
        return self.client.post("/oauth/token", data=data)

    def test_pkce_s256(self):
        verifier = "a" * 43
        code = self.issue_pkce_code(verifier)
        rv = self.exchange_pkce_code(code, verifier)
        assert b"access_token" in rv.data

    def test_pkce_rejects_missing_or_wrong_verifier(self):
        verifier = "a" * 43
        rv = self.exchange_pkce_code(self.issue_pkce_code(verifier))
        assert b"Missing 'code_verifier'" in rv.data

        rv = self.exchange_pkce_code(self.issue_pkce_code(verifier), "b" * 43)
        assert b"invalid_grant" in rv.data

    def test_get_token(self):
        url = self.authorize_url + "&scope=email"
        self.client.get(url)
        rv = self.client.post(url, data={"confirm": "yes"})
        assert "code" in rv.location
        code = rv.location.split("code=")[1]

        url = (
            "/oauth/token?grant_type=authorization_code"
            "&code=%s&client_id=%s"
            "&redirect_uri=http%%3A%%2F%%2Flocalhost%%2Fauthorized"
        ) % (code, self.oauth_client.client_id)
        rv = self.client.get(url)
        assert b"invalid_client" in rv.data

        url += "&client_secret=" + self.oauth_client.client_secret
        rv = self.client.get(url)
        assert b"access_token" in rv.data


class TestProviderWithExceptionHandler(TestCase):

    def prepare_data(self):
        oauth = default_provider(self.app)

        @oauth.exception_handler
        def custom_exception_handler(error, *args):
            raise error

        @self.app.errorhandler(Exception)
        def all_exception_handler(*args):
            return "Testing server error", 500

        create_server(self.app, oauth=oauth)

    def test_exception_handler(self):
        rv = self.client.get("/oauth/authorize")

        assert rv.status_code == 500
        assert rv.data.decode("utf-8") == "Testing server error"
