"""Durable local store (SQLite, WAL). All SQL is parameterized.

One connection per Store guarded by an RLock; independent Store objects on the same file
coordinate through SQLite's own locking (BEGIN IMMEDIATE + busy_timeout). Workflow updates use
compare-and-set on the current state so concurrent writers cannot both win.

Durability note: synchronous=NORMAL in WAL mode can lose the last transactions on OS crash
(not on process crash). Documented trade-off for a local companion.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sedei.events import EventEnvelope, canonical_json, to_dt, to_epoch

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant TEXT NOT NULL, event_id TEXT NOT NULL, type TEXT NOT NULL, emitter TEXT NOT NULL,
  event_time REAL NOT NULL, ingest_time REAL NOT NULL,
  correlation_id TEXT NOT NULL, causation_id TEXT, schema_version TEXT NOT NULL,
  payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
  UNIQUE(tenant, event_id));
CREATE TABLE IF NOT EXISTS deliveries(
  tenant TEXT NOT NULL, event_id TEXT NOT NULL, consumer TEXT NOT NULL,
  state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  available_at REAL NOT NULL, lease_expires REAL, last_error TEXT, acked_at REAL,
  PRIMARY KEY(tenant, event_id, consumer));
CREATE INDEX IF NOT EXISTS ix_deliv ON deliveries(consumer, state, available_at);
CREATE TABLE IF NOT EXISTS dead_letters(
  tenant TEXT, event_id TEXT, consumer TEXT, attempts INTEGER, error TEXT, dead_at REAL,
  PRIMARY KEY(tenant, event_id, consumer));
CREATE TABLE IF NOT EXISTS processed(
  consumer TEXT NOT NULL, tenant TEXT NOT NULL, event_id TEXT NOT NULL, processed_at REAL,
  PRIMARY KEY(consumer, tenant, event_id));
CREATE TABLE IF NOT EXISTS workflows(
  workflow_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, idempotency_key TEXT NOT NULL,
  principal TEXT NOT NULL, state TEXT NOT NULL, correlation_id TEXT NOT NULL,
  payload_json TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
  version INTEGER NOT NULL DEFAULT 0, UNIQUE(tenant, idempotency_key));
CREATE TABLE IF NOT EXISTS transitions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, workflow_id TEXT NOT NULL,
  from_state TEXT, to_state TEXT NOT NULL, event_id TEXT, at REAL NOT NULL, policy_version TEXT);
CREATE TABLE IF NOT EXISTS reservations(
  tenant TEXT NOT NULL, workflow_id TEXT NOT NULL, sku TEXT, qty INTEGER, at REAL,
  PRIMARY KEY(tenant, workflow_id));
CREATE TABLE IF NOT EXISTS telemetry(
  record_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, principal TEXT NOT NULL, kind TEXT NOT NULL,
  event_time REAL NOT NULL, receipt_time REAL NOT NULL, late INTEGER NOT NULL, body_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_tel ON telemetry(tenant, principal, receipt_time);
CREATE TABLE IF NOT EXISTS controls(
  control_type TEXT NOT NULL, tenant TEXT NOT NULL, target TEXT NOT NULL,
  action_id TEXT, params_json TEXT, active INTEGER NOT NULL,
  PRIMARY KEY(control_type, tenant, target));
CREATE TABLE IF NOT EXISTS decisions(
  decision_id TEXT PRIMARY KEY, incident_key TEXT NOT NULL, tenant TEXT NOT NULL,
  action_type TEXT, target_kind TEXT, target_id TEXT, risk REAL, policy_version TEXT,
  evidence_json TEXT, reason_json TEXT, decided_sim REAL, decided_wall REAL);
CREATE TABLE IF NOT EXISTS actions(
  action_id TEXT PRIMARY KEY, dedup_key TEXT NOT NULL UNIQUE, decision_id TEXT NOT NULL,
  action_type TEXT NOT NULL, tenant TEXT NOT NULL, target_kind TEXT NOT NULL, target_id TEXT NOT NULL,
  status TEXT NOT NULL, committed_sim REAL, committed_wall REAL, expires_at REAL, note TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL,
  principal TEXT, tenant TEXT, policy_version TEXT, scope TEXT, evidence_json TEXT, detail_json TEXT,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""


class ConflictError(RuntimeError):
    """Optimistic-concurrency failure: the row was not in the expected state."""


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._depth = 0
        self._conn.execute("PRAGMA busy_timeout=10000")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def txn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._depth > 0:
                self._depth += 1
                try:
                    yield self._conn
                finally:
                    self._depth -= 1
                return
            self._conn.execute("BEGIN IMMEDIATE")
            self._depth = 1
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            finally:
                self._depth = 0

    def q(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def q1(self, sql: str, params: tuple | dict = ()) -> sqlite3.Row | None:
        rows = self.q(sql, params)
        return rows[0] if rows else None

    # ---- events and deliveries -------------------------------------------------------------
    def append_event(self, env: EventEnvelope, consumers: list[str], now: float) -> bool:
        """Insert event + one delivery per consumer atomically. False if event_id already exists."""
        with self.txn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO events(tenant,event_id,type,emitter,event_time,ingest_time,"
                "correlation_id,causation_id,schema_version,payload_json,payload_sha256) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (env.tenant, env.event_id, env.type, env.emitter, to_epoch(env.event_time),
                 to_epoch(env.ingest_time), env.correlation_id, env.causation_id,
                 env.schema_version, canonical_json(env.payload), env.payload_sha256()),
            )
            if cur.rowcount == 0:
                return False
            for consumer in consumers:
                c.execute(
                    "INSERT INTO deliveries(tenant,event_id,consumer,state,available_at) "
                    "VALUES(?,?,?,?,?)",
                    (env.tenant, env.event_id, consumer, "pending", now),
                )
            return True

    def get_event(self, tenant: str, event_id: str) -> EventEnvelope | None:
        r = self.q1("SELECT * FROM events WHERE tenant=? AND event_id=?", (tenant, event_id))
        if r is None:
            return None
        return EventEnvelope(
            event_id=r["event_id"], tenant=r["tenant"], emitter=r["emitter"], type=r["type"],
            event_time=to_dt(r["event_time"]), ingest_time=to_dt(r["ingest_time"]),
            correlation_id=r["correlation_id"], causation_id=r["causation_id"],
            schema_version=r["schema_version"], payload=json.loads(r["payload_json"]),
        )

    def claim(self, consumer: str, now: float, lease_s: float, limit: int = 10) -> list[dict[str, Any]]:
        with self.txn() as c:
            rows = c.execute(
                "SELECT tenant,event_id,attempts FROM deliveries WHERE consumer=? AND "
                "((state='pending' AND available_at<=?) OR (state='leased' AND lease_expires<=?)) "
                "ORDER BY available_at, tenant, event_id LIMIT ?",
                (consumer, now, now, limit),
            ).fetchall()
            out = []
            for r in rows:
                c.execute(
                    "UPDATE deliveries SET state='leased', attempts=attempts+1, lease_expires=? "
                    "WHERE tenant=? AND event_id=? AND consumer=?",
                    (now + lease_s, r["tenant"], r["event_id"], consumer),
                )
                out.append({"tenant": r["tenant"], "event_id": r["event_id"],
                            "attempt": r["attempts"] + 1})
            return out

    def ack(self, consumer: str, tenant: str, event_id: str, now: float) -> None:
        with self.txn() as c:
            c.execute(
                "UPDATE deliveries SET state='acked', acked_at=? WHERE tenant=? AND event_id=? "
                "AND consumer=? AND state='leased'",
                (now, tenant, event_id, consumer),
            )

    def nack(self, consumer: str, tenant: str, event_id: str, error: str, now: float,
             max_attempts: int, backoff_base_s: float) -> str:
        with self.txn() as c:
            r = c.execute(
                "SELECT attempts FROM deliveries WHERE tenant=? AND event_id=? AND consumer=?",
                (tenant, event_id, consumer),
            ).fetchone()
            attempts = r["attempts"]
            if attempts >= max_attempts:
                c.execute(
                    "UPDATE deliveries SET state='dead', last_error=? WHERE tenant=? AND event_id=? "
                    "AND consumer=?", (error[:500], tenant, event_id, consumer))
                c.execute(
                    "INSERT OR REPLACE INTO dead_letters VALUES(?,?,?,?,?,?)",
                    (tenant, event_id, consumer, attempts, error[:500], now))
                return "dead"
            c.execute(
                "UPDATE deliveries SET state='pending', available_at=?, last_error=? "
                "WHERE tenant=? AND event_id=? AND consumer=?",
                (now + backoff_base_s * 2 ** (attempts - 1), error[:500], tenant, event_id, consumer))
            return "retry"

    def quarantine_event(self, tenant: str, event_id: str) -> int:
        with self.txn() as c:
            cur = c.execute(
                "UPDATE deliveries SET state='quarantined' WHERE tenant=? AND event_id=? "
                "AND state IN ('pending','leased')", (tenant, event_id))
            return cur.rowcount

    def release_quarantine(self, tenant: str, event_id: str, now: float) -> int:
        with self.txn() as c:
            cur = c.execute(
                "UPDATE deliveries SET state='pending', available_at=? WHERE tenant=? AND event_id=? "
                "AND state='quarantined'", (now, tenant, event_id))
            return cur.rowcount

    def backlog(self, consumer: str | None = None) -> int:
        sql = "SELECT COUNT(*) n FROM deliveries WHERE state IN ('pending','leased')"
        params: tuple = ()
        if consumer:
            sql += " AND consumer=?"
            params = (consumer,)
        return int(self.q1(sql, params)["n"])

    def mark_processed(self, consumer: str, tenant: str, event_id: str, now: float) -> bool:
        with self.txn() as c:
            cur = c.execute("INSERT OR IGNORE INTO processed VALUES(?,?,?,?)",
                            (consumer, tenant, event_id, now))
            return cur.rowcount == 1

    # ---- workflows --------------------------------------------------------------------------
    def create_workflow(self, workflow_id: str, tenant: str, idem_key: str, principal: str,
                        correlation_id: str, payload: dict, state: str, now: float) -> tuple[str, bool]:
        with self.txn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO workflows(workflow_id,tenant,idempotency_key,principal,state,"
                "correlation_id,payload_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (workflow_id, tenant, idem_key, principal, state, correlation_id,
                 canonical_json(payload), now, now))
            if cur.rowcount == 1:
                c.execute("INSERT INTO transitions(workflow_id,from_state,to_state,at) VALUES(?,?,?,?)",
                          (workflow_id, None, state, now))
                return workflow_id, True
            r = c.execute("SELECT workflow_id FROM workflows WHERE tenant=? AND idempotency_key=?",
                          (tenant, idem_key)).fetchone()
            return r["workflow_id"], False

    def transition(self, workflow_id: str, expected: str, new: str, event_id: str | None,
                   now: float, policy_version: str) -> None:
        with self.txn() as c:
            cur = c.execute(
                "UPDATE workflows SET state=?, version=version+1, updated_at=? "
                "WHERE workflow_id=? AND state=?", (new, now, workflow_id, expected))
            if cur.rowcount != 1:
                raise ConflictError(f"{workflow_id} not in state {expected}")
            c.execute(
                "INSERT INTO transitions(workflow_id,from_state,to_state,event_id,at,policy_version) "
                "VALUES(?,?,?,?,?,?)", (workflow_id, expected, new, event_id, now, policy_version))

    def get_workflow(self, workflow_id: str) -> sqlite3.Row | None:
        return self.q1("SELECT * FROM workflows WHERE workflow_id=?", (workflow_id,))

    # ---- telemetry --------------------------------------------------------------------------
    def insert_telemetry(self, record_id: str, tenant: str, principal: str, kind: str,
                         event_time: float, receipt_time: float, late: bool, body: dict) -> bool:
        with self.txn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO telemetry VALUES(?,?,?,?,?,?,?,?)",
                (record_id, tenant, principal, kind, event_time, receipt_time, int(late),
                 canonical_json(body)))
            return cur.rowcount == 1

    # ---- controls (state changes made by adaptive response) ------------------------------------
    def set_control(self, control_type: str, tenant: str, target: str, action_id: str,
                    params: dict | None = None) -> None:
        with self.txn() as c:
            c.execute("INSERT OR REPLACE INTO controls VALUES(?,?,?,?,?,1)",
                      (control_type, tenant, target, action_id, canonical_json(params or {})))

    def clear_control(self, control_type: str, tenant: str, target: str) -> None:
        with self.txn() as c:
            c.execute("UPDATE controls SET active=0 WHERE control_type=? AND tenant=? AND target=?",
                      (control_type, tenant, target))

    def set_action_status(self, action_id: str, status: str) -> None:
        with self.txn() as c:
            c.execute("UPDATE actions SET status=? WHERE action_id=?", (status, action_id))

    def get_control(self, control_type: str, tenant: str, target: str) -> dict | None:
        r = self.q1("SELECT * FROM controls WHERE control_type=? AND tenant=? AND target=? AND active=1",
                    (control_type, tenant, target))
        return None if r is None else {"action_id": r["action_id"],
                                       "params": json.loads(r["params_json"] or "{}")}
