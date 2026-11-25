"""DEMO identity service: HMAC-signed bearer tokens from a declared local test issuer.

This is NOT an identity provider. It exists so the local gateway can authenticate fixture
identities without any external service. The default signing key is a published demo constant
(never a secret); override with SEDEI_DEMO_ISSUER_KEY. Do not reuse it anywhere real.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from sedei.config import CONFIG_DIR, load_yaml

DEMO_KEY = b"sedei-local-demo-issuer-key-not-a-secret"
ISSUER = "sedei-test-issuer"


class AuthError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str
    scopes: frozenset[str]
    kind: str
    privilege: str
    stepup: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return (self.tenant, self.subject)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class TestIssuer:
    __test__ = False  # not a pytest class

    def __init__(self, key: bytes | None = None, fixtures_path: Path | None = None) -> None:
        env = os.environ.get("SEDEI_DEMO_ISSUER_KEY")
        self._key = key or (env.encode() if env else DEMO_KEY)
        d = load_yaml(fixtures_path or CONFIG_DIR / "identities.yaml")
        self.fixtures = {(i["tenant"], i["subject"]): i for i in d["identities"]}
        self.fixture_services = frozenset(d["fixture_services"])

    def is_fixture_identity(self, tenant: str, subject: str) -> bool:
        return (tenant, subject) in self.fixtures

    def issue(self, tenant: str, subject: str, now: float, ttl_s: float = 900.0,
              stepup: bool = False) -> str:
        fx = self.fixtures.get((tenant, subject))
        if fx is None:
            raise AuthError("not_a_fixture_identity")
        claims = {"iss": ISSUER, "sub": subject, "ten": tenant, "scp": sorted(fx["scopes"]),
                  "knd": fx["kind"], "prv": fx["privilege"], "exp": now + ttl_s, "stu": stepup}
        body = _b64(json.dumps(claims, sort_keys=True).encode())
        sig = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        return f"v1.{body}.{sig}"

    def verify(self, token: str, now: float) -> Principal:
        try:
            ver, body, sig = token.split(".")
        except ValueError:
            raise AuthError("malformed_token") from None
        if ver != "v1":
            raise AuthError("malformed_token")
        expect = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expect, sig):
            raise AuthError("bad_signature")
        try:
            c = json.loads(_unb64(body))
        except (ValueError, json.JSONDecodeError):
            raise AuthError("malformed_token") from None
        if c.get("iss") != ISSUER:
            raise AuthError("bad_issuer")
        if now >= float(c["exp"]):
            raise AuthError("token_expired")
        return Principal(c["sub"], c["ten"], frozenset(c["scp"]), c["knd"], c["prv"], bool(c["stu"]))
