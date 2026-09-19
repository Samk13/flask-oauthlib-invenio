from urllib.parse import parse_qs, urlparse

import pytest
from authlib.oauth1.rfc5849.signature import verify_hmac_sha1, verify_rsa_sha1
from authlib.oauth1.rfc5849.wrapper import OAuth1Request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask

from flask_oauthlib.client import (
    OAuth,
    OAuthException,
    OAuthRemoteApp,
    encode_request_data,
    parse_response,
)

try:
    import urllib2 as http

    http_urlopen = "urllib2.urlopen"
except ImportError:
    from urllib import request as http

    http_urlopen = "urllib.request.urlopen"

from mock import MagicMock, patch


class Response(object):
    def __init__(self, content, headers=None):
        self.content = content
        self.headers = headers or {}

    @property
    def code(self):
        return self.headers.get("status-code", 500)

    @property
    def status_code(self):
        return self.code

    def read(self):
        return self.content

    def close(self):
        return self


def test_encode_request_data():
    data, _ = encode_request_data("foo", None)
    assert data == "foo"

    data, f = encode_request_data(None, "json")
    assert data == "{}"
    assert f == "application/json"

    data, f = encode_request_data(None, "urlencoded")
    assert data == ""
    assert f == "application/x-www-form-urlencoded"


def test_app():
    app = Flask(__name__)
    oauth = OAuth(app)
    remote = oauth.remote_app(
        "dev",
        consumer_key="dev",
        consumer_secret="dev",
        request_token_params={"scope": "email"},
        base_url="http://127.0.0.1:5000/api/",
        request_token_url=None,
        access_token_method="POST",
        access_token_url="http://127.0.0.1:5000/oauth/token",
        authorize_url="http://127.0.0.1:5000/oauth/authorize",
    )
    client = app.extensions["oauthlib.client"]
    assert client.dev.name == "dev"


def test_parse_xml():
    resp = Response(
        "<foo>bar</foo>", headers={"status-code": 200, "content-type": "text/xml"}
    )
    parse_response(resp, resp.read())


def test_raise_app():
    app = Flask(__name__)
    oauth = OAuth(app)
    client = app.extensions["oauthlib.client"]
    with pytest.raises(AttributeError):
        client.demo


class TestOAuthRemoteApp(object):
    def test_raise_init(self):
        with pytest.raises(TypeError):
            OAuthRemoteApp("oauth", "twitter")

    def test_not_raise_init(self):
        OAuthRemoteApp("oauth", "twitter", app_key="foo")

    def test_lazy_load(self):
        oauth = OAuth()
        twitter = oauth.remote_app(
            "twitter", base_url="https://api.twitter.com/1/", app_key="twitter"
        )
        assert twitter.base_url == "https://api.twitter.com/1/"

        app = Flask(__name__)
        app.config.update(
            {
                "twitter": dict(
                    request_token_params={"realms": "email"},
                    consumer_key="twitter key",
                    consumer_secret="twitter secret",
                    request_token_url="request url",
                    access_token_url="token url",
                    authorize_url="auth url",
                )
            }
        )
        oauth.init_app(app)
        assert twitter.consumer_key == "twitter key"
        assert twitter.consumer_secret == "twitter secret"
        assert twitter.request_token_url == "request url"
        assert twitter.access_token_url == "token url"
        assert twitter.authorize_url == "auth url"
        assert twitter.content_type is None
        assert "realms" in twitter.request_token_params

    def test_lazy_load_with_plain_text_config(self):
        oauth = OAuth()
        twitter = oauth.remote_app("twitter", app_key="TWITTER")

        app = Flask(__name__)
        app.config["TWITTER_CONSUMER_KEY"] = "twitter key"
        app.config["TWITTER_CONSUMER_SECRET"] = "twitter secret"
        app.config["TWITTER_REQUEST_TOKEN_URL"] = "request url"
        app.config["TWITTER_ACCESS_TOKEN_URL"] = "token url"
        app.config["TWITTER_AUTHORIZE_URL"] = "auth url"

        oauth.init_app(app)

        assert twitter.consumer_key == "twitter key"
        assert twitter.consumer_secret == "twitter secret"
        assert twitter.request_token_url == "request url"
        assert twitter.access_token_url == "token url"
        assert twitter.authorize_url == "auth url"

    @patch(http_urlopen)
    def test_http_request(self, urlopen):
        urlopen.return_value = Response(b'{"foo": "bar"}', headers={"status-code": 200})

        resp, content = OAuthRemoteApp.http_request("http://example.com")
        assert resp.code == 200
        assert b"foo" in content

        resp, content = OAuthRemoteApp.http_request(
            "http://example.com/", method="GET", data={"wd": "flask-oauthlib"}
        )
        assert resp.code == 200
        assert b"foo" in content

        resp, content = OAuthRemoteApp.http_request(
            "http://example.com/", data={"wd": "flask-oauthlib"}
        )
        assert resp.code == 200
        assert b"foo" in content

    @patch(http_urlopen)
    def test_raise_http_request(self, urlopen):
        error = http.HTTPError("http://example.com/", 404, "Not Found", None, None)
        error.read = lambda: b"o"

        class _Fake(object):
            def close(self):
                return 0

        class _Faker(object):
            _closer = _Fake()

        error.file = _Faker()

        urlopen.side_effect = error
        resp, content = OAuthRemoteApp.http_request("http://example.com")
        assert resp.code == 404
        assert b"o" in content

    def test_oauth2_state_mismatch_never_exchanges_code(self):
        app = Flask(__name__)
        app.secret_key = "test"
        oauth = OAuth(app)
        remote = oauth.remote_app(
            "remote",
            consumer_key="key",
            consumer_secret="secret",
            request_token_url=None,
            access_token_url="https://provider.example/token",
            authorize_url="https://provider.example/authorize",
        )
        _ = remote.authlib_client
        remote.http_request = lambda *args, **kwargs: pytest.fail(
            "state mismatch must not trigger a token request"
        )

        with app.test_request_context("/callback?code=valid&state=tampered"):
            with pytest.raises(OAuthException) as exc:
                remote.authorized_response()

        assert exc.value.type == "mismatching_state"

    def test_oidc_callback_preserves_nonce_validation(self):
        app = Flask(__name__)
        app.secret_key = "test"
        oauth = OAuth(app)
        remote = oauth.remote_app(
            "oidc",
            consumer_key="key",
            consumer_secret="secret",
            request_token_url=None,
            access_token_url="https://provider.example/token",
            authorize_url="https://provider.example/authorize",
            request_token_params={"scope": "openid profile"},
            parse_id_token=True,
            server_metadata_url="https://provider.example/.well-known/openid-configuration",
        )
        remote._fetch_oauth2_token = MagicMock(
            return_value={"access_token": "token", "id_token": "signed-token"}
        )
        remote.authlib_client.load_server_metadata = MagicMock(
            return_value={
                "authorization_endpoint": "https://provider.example/authorize",
                "token_endpoint": "https://provider.example/token",
            }
        )
        remote.authlib_client.parse_id_token = MagicMock(return_value={"sub": "123"})

        @app.route("/login")
        def login():
            return remote.authorize("http://localhost/callback")

        @app.route("/callback")
        def callback():
            token = remote.authorized_response()
            assert token["userinfo"] == {"sub": "123"}
            return "ok"

        with app.test_client() as client:
            response = client.get("/login")
            state = parse_qs(urlparse(response.location).query)["state"][0]
            response = client.get(f"/callback?code=valid&state={state}")

        assert response.status_code == 200
        kwargs = remote.authlib_client.parse_id_token.call_args.kwargs
        assert kwargs["nonce"]

    @pytest.mark.parametrize("signature_method", ["HMAC-SHA1", "RSA-SHA1"])
    def test_oauth1_signatures_are_verifiable(self, signature_method):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        oauth = OAuth()
        remote = oauth.remote_app(
            "remote",
            consumer_key="key",
            consumer_secret="secret",
            request_token_url="https://provider.example/request-token",
            rsa_key=private_pem,
            signature_method=signature_method,
        )

        uri, headers, body = remote._oauth1_auth().prepare(
            "POST", "https://provider.example/resource", {}, b"value=1"
        )
        signed_request = OAuth1Request("POST", uri, body, headers)

        class Client:
            def get_client_secret(self):
                return "secret"

            def get_rsa_public_key(self):
                return public_pem

        signed_request.client = Client()
        verifier = (
            verify_rsa_sha1 if signature_method == "RSA-SHA1" else verify_hmac_sha1
        )
        assert verifier(signed_request)

    def test_token_types(self):
        oauth = OAuth()
        remote = oauth.remote_app(
            "remote", consumer_key="remote key", consumer_secret="remote secret"
        )

        client_token = {"access_token": "access token"}

        str_token = "access token"
        client = remote.make_client(token=str_token)
        assert client.token == client_token

        list_token = ["access token"]
        client = remote.make_client(token=list_token)
        assert client.token == client_token

        tuple_token = ("access token",)
        client = remote.make_client(token=tuple_token)
        assert client.token == client_token

        dict_token = {"access_token": "access token"}
        client = remote.make_client(token=dict_token)
        assert client.token == client_token

    def test_custom_remote_app_hooks_are_preserved(self):
        class CustomRemoteApp(OAuthRemoteApp):
            calls = []

            def expand_url(self, url):
                self.calls.append(("expand_url", url))
                return "http://example.org/custom/" + url

            def pre_request(self, uri, headers, data):
                self.calls.append(("pre_request", uri))
                headers["X-Custom-Provider"] = "yes"
                return uri, headers, data

            def http_request(self, uri, headers=None, data=None, method=None):
                self.calls.append(("http_request", uri, headers, method))
                return (
                    Response(
                        b'{"ok": true}',
                        headers={
                            "status-code": 200,
                            "content-type": "application/json",
                        },
                    ),
                    b'{"ok": true}',
                )

        oauth = OAuth()
        remote = CustomRemoteApp(
            oauth,
            "custom",
            consumer_key="custom-key",
            consumer_secret="custom-secret",
            request_token_url=None,
            base_url="http://example.org/",
            access_token_url="http://example.org/token",
            authorize_url="http://example.org/authorize",
        )

        @remote.tokengetter
        def get_token():
            return "token"

        response = remote.get("profile")
        assert response.status == 200
        assert response.data["ok"] is True
        assert ("expand_url", "profile") in remote.calls
        assert remote.calls[-1][0] == "http_request"
        assert remote.calls[-1][2]["X-Custom-Provider"] == "yes"
