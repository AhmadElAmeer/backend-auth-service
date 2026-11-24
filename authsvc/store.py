"""SQLite storage. Every operation runs in its own short transaction; anything
that reads and then writes security state (failure counters, one-time codes)
uses BEGIN IMMEDIATE so concurrent requests are serialised by the database.

Secrets are never stored in a usable form:
  - passwords as scrypt hashes;
  - session, MFA-challenge and reset tokens as SHA-256 hashes (they are long
    random strings, so a fast hash is enough; a stolen database can't be used
    to log in as anyone);
  - TOTP keys encrypted with AES-GCM under a key that isn't in the database.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id                  INTEGER PRIMARY KEY,
  username            TEXT NOT NULL UNIQUE,      -- normalised (NFKC + casefold)
  display_name        TEXT NOT NULL,             -- as typed at registration
  email               TEXT NOT NULL UNIQUE,      -- normalised (lower-case)
  password_hash       TEXT NOT NULL,
  created_at          REAL NOT NULL,
  password_changed_at REAL NOT NULL,
  totp_secret         BLOB,                      -- AES-GCM ciphertext; NULL = no 2FA
  totp_pending        BLOB,                      -- set during enrolment, before confirmation
  totp_last_step      INTEGER                    -- last accepted time step (replay protection)
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  public_id   TEXT NOT NULL UNIQUE,              -- shown in "your sessions"; not a credential
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_hash   TEXT NOT NULL,
  created_at  REAL NOT NULL,
  last_seen   REAL NOT NULL,
  ip          TEXT,
  user_agent  TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS mfa_challenges (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  REAL NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  ip          TEXT,
  user_agent  TEXT
);
CREATE TABLE IF NOT EXISTS recovery_codes (
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash   TEXT NOT NULL,
  used_at     REAL,
  PRIMARY KEY (user_id, code_hash)
);
-- Keyed by the normalised username *whether or not the account exists*, so
-- lockout behaves identically for real and made-up names.
CREATE TABLE IF NOT EXISTS login_failures (
  username_key  TEXT PRIMARY KEY,
  count         INTEGER NOT NULL,
  locked_until  REAL NOT NULL DEFAULT 0,
  last_failure  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_failures (
  ip  TEXT NOT NULL,
  ts  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ip_failures_ip_ts ON ip_failures(ip, ts);
CREATE TABLE IF NOT EXISTS reset_tokens (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  REAL NOT NULL,
  used_at     REAL
);
CREATE TABLE IF NOT EXISTS outbox (          -- e-mails to send (a worker would deliver them)
  id          INTEGER PRIMARY KEY,
  to_addr     TEXT NOT NULL,
  subject     TEXT NOT NULL,
  body        TEXT NOT NULL,
  created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id       INTEGER PRIMARY KEY,
  ts       REAL NOT NULL,
  user_id  INTEGER,
  event    TEXT NOT NULL,
  ip       TEXT,
  detail   TEXT
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def read(self):
        """A connection for reads only (autocommit), closed afterwards."""
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def tx(self, immediate: bool = True):
        """A transaction on a fresh connection. IMMEDIATE takes the write lock up
        front, so a read-check-write sequence can't interleave with another one."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
