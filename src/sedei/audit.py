"""Append-only, hash-chained audit log. Every state change records evidence, principal, policy version, scope."""

from __future__ import annotations

import hashlib
import json
import sqlite3

from sedei.events import canonical_json
from sedei.store import Store

GENESIS = "0" * 64


def append(store: Store, *, at: float, kind: str, actor: str, principal: str | None, tenant: str | None,
           policy_version: str, scope: str, evidence: list[str], detail: dict) -> str:
    with store.txn() as c:
        row = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        payload = canonical_json({"at": at, "kind": kind, "actor": actor, "principal": principal,
                                  "tenant": tenant, "policy_version": policy_version, "scope": scope,
                                  "evidence": evidence, "detail": detail, "prev": prev})
        h = hashlib.sha256(payload.encode()).hexdigest()
        c.execute(
            "INSERT INTO audit(at,kind,actor,principal,tenant,policy_version,scope,evidence_json,"
            "detail_json,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (at, kind, actor, principal, tenant, policy_version, scope, json.dumps(evidence),
             canonical_json(detail), prev, h))
        return h


def verify_chain(store: Store) -> bool:
    prev = GENESIS
    for r in store.q("SELECT * FROM audit ORDER BY id"):
        payload = canonical_json({
            "at": r["at"], "kind": r["kind"], "actor": r["actor"], "principal": r["principal"],
            "tenant": r["tenant"], "policy_version": r["policy_version"], "scope": r["scope"],
            "evidence": json.loads(r["evidence_json"]), "detail": json.loads(r["detail_json"]),
            "prev": prev})
        if r["prev_hash"] != prev or hashlib.sha256(payload.encode()).hexdigest() != r["hash"]:
            return False
        prev = r["hash"]
    return True


def entries(store: Store) -> list[sqlite3.Row]:
    return store.q("SELECT * FROM audit ORDER BY id")
