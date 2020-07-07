#
#
#
import base64
import json
import logging
import typing

import httpx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from jose import jose_jwt
from jose.exceptions import JWTError
from starlette.datastructures import Headers
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Receive, Scope, Send

from ._exceptions import InvalidAuthorizationToken
from ._models import AadAccessToken, AadUser, AzureAdJWKS, AzureAdKey, OpenIdConnect

logger = logging.getLogger(__name__)


BASE_URL = "https://login.microsoftonline.com/{}/.well-known/openid-configuration"
_cache = {}


class BaseMiddleware:
    def __init__(
        self, app: ASGIApp, tenant_id: str, client_id: str, discovery_endpoint: str = None,
    ):
        self._app = app
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._discovery_endpoint = discovery_endpoint if discovery_endpoint else BASE_URL.format(tenant_id)

    def ensure_bytes(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return value

    def decode_value(self, value):
        decoded = base64.urlsafe_b64decode(self.ensure_bytes(value) + b"==")
        return int.from_bytes(decoded, "big")

    def rsa_pem_from_jwk(self, jwk: AzureAdKey):
        return (
            RSAPublicNumbers(n=self.decode_value(jwk.n), e=self.decode_value(jwk.e))
            .public_key(default_backend())
            .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo,)
        )

    def get_jwt(self, header: Headers) -> str:
        if "Authorization" not in header:
            return

        token = header.get("Authorization")
        scheme, jwt = token.split()
        if scheme.lower() != "bearer":
            raise InvalidAuthorizationToken(
                "header dose not start \
                with 'Bearer'"
            )

        return jwt

    async def get_issuer(self) -> typing.Tuple[str, str]:
        metadata = await self.get_openid_connect_metadata()
        return metadata.issuer

    async def get_openid_connect_metadata(self, *, force=False) -> OpenIdConnect:
        if force:
            _cache = {}

        if "metadata" in _cache:
            return _cache["metadata"]

        async with httpx.AsyncClient() as client:
            logger.info("Getting OpenId Connect metadata for Azure AD")
            resp: httpx.Response = await client.get(self._discovery_endpoint)
            model = OpenIdConnect(**json.loads(resp.json()))
            _cache["metadata"] = model

        return model

    async def get_ad_key(self, kid: str) -> AzureAdKey:
        if "keys" in _cache and kid in _cache:
            return _cache[kid]

        key = await self._get_key(kid)
        if key:
            return key

        jwks_uri = await self.get_openid_connect_metadata().jwks_uri

        async with httpx.AsyncClient as client:
            resp: httpx.Response = client.get(jwks_uri)
            model = AzureAdJWKS(**json.loads(resp.json()))
            _cache["keys"] = model

        key = await self._get_key(kid)
        if key:
            return key
        else:
            raise InvalidAuthorizationToken("could not get the key from azure ad")

    async def _get_key(self, kid: str):
        if "keys" in _cache:
            for key in _cache["keys"]:
                if kid == key.kid:
                    _cache[kid] = key
                    _cache["keys"].remove(key)
                    return key
        else:
            logger.info(
                "Could not find the correct key, refresh OpenId \
                Connect metadata."
            )
            await self.get_openid_connect_metadata(force=True)

        return None


class VerifyAzureAdJWT(BaseMiddleware):
    def __init__(
        self, app: ASGIApp, tenant_id: str, client_id: str, discovery_endpoint: str = None,
    ):
        super().__init__(app, tenant_id, client_id, discovery_endpoint)

    async def __call__(self, scope: Scope, recive: Receive, send: Send):
        if scope["type"] not in ("http", "websocket"):
            await self._app(scope, recive, send)
            return

        conn = HTTPConnection(scope)
        token = self.get_jwt(conn.headers)

        token_headers = jose_jwt.get_unverified_headers(token)
        if not token_headers:
            raise InvalidAuthorizationToken("jwt headers missing")

        try:
            kid = token_headers["kid"]
        except KeyError:
            raise InvalidAuthorizationToken("kid missing from jwt header")

        key_info = await self.get_ad_key(kid)
        public_key = self.rsa_pem_from_jwk(key_info)
        issuer = await self.get_issuer()
        audience = self._client_id

        try:
            decoded = jose_jwt.decode(
                token, public_key, verify=True, algorithms=["RS256"], audience=audience, issuer=issuer,
            )

            access_token = AadAccessToken(**decoded)
            user = AadUser(access_token)
        except JWTError as e:
            raise InvalidAuthorizationToken(e.__class__.__name__)

        scope["user"] = user
        await self._app(scope, recive, send)
