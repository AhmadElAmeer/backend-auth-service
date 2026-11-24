"""The authentication service: accounts, logins with throttling, sessions,
password changes and resets, and TOTP two-factor authentication.

It knows nothing about HTTP; `web.py` maps it onto a JSON API. Time comes
from an injectable clock so tests can move it forward deterministically.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import passwords, totp
from .store import Store


# ---------------------------------------------------------------- errors

class AuthError(Exception):
    status = 400
    code = "bad_request"

    def __init__(self, message: str = "", **extra):
        super().__init__(message or self.code)
        self.message = message or self.code
        self.extra = extra


class InvalidCredentials(AuthError):
    status, code = 401, "invalid_credentials"

    def __init__(self, message: str = "Incorrect username or password."):
        # One message for every reason (no such user or wrong password), so
        # responses don't reveal which accounts exist.
        super().__init__(message)


class TooManyAttempts(AuthError):
    status, code = 429, "too_many_attempts"

    def __init__(self, retry_after: float):
        seconds = max(1, math.ceil(retry_after))
        super().__init__(f"Too many failed attempts. Try again in {seconds} s.", retry_after=seconds)


class PolicyError(AuthError):
    status, code = 400, "weak_password"

    def __init__(self, problems: list[str]):
        super().__init__("Password " + "; ".join(problems) + ".", problems=problems)


class Conflict(AuthError):
    status, code = 409, "conflict"


class NotAuthenticated(AuthError):
    status, code = 401, "not_authenticated"


class InvalidToken(AuthError):
    status, code = 400, "invalid_token"


# ---------------------------------------------------------------- config and results

@dataclass
class Config:
    hash_params: passwords.ScryptParams = field(default_factory=passwords.ScryptParams)
    session_idle: float = 30 * 60           # log out after 30 minutes of inactivity
    session_absolute: float = 12 * 3600     # and after 12 hours regardless
    touch_interval: float = 60              # write last_seen at most once a minute
    lock_threshold: int = 5                 # failures before the first lock
    lock_base: float = 1.0                  # first lock: 1 s, then doubling...
    lock_max: float = 15 * 60               # ...up to 15 minutes
    ip_window: float = 15 * 60
    ip_max_failures: int = 100              # per IP per window, across all usernames
    reset_ttl: float = 30 * 60
    mfa_ttl: float = 5 * 60
    mfa_max_attempts: int = 5
    recovery_codes: int = 10
    max_concurrent_hashes: int = 4         # scrypt is memory-hard: 4 x 128 MiB at most
    issuer: str = "authsvc"
    reset_url: str = "https://localhost/reset?token="
    data_key: bytes = b""                   # 32 bytes for AES-GCM; required to use 2FA


@dataclass
class Session:
    token: str          # goes in the cookie; only its hash is stored
    csrf_token: str     # returned once; the client sends it back in a header
    public_id: str
    user_id: int


@dataclass
class LoginResult:
    session: Session | None = None
    mfa_token: str | None = None    # set when a second factor is still needed


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_username(name: str) -> str:
    return unicodedata.normalize("NFKC", name).strip().casefold()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def _recovery_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O or 1/I to misread
    raw = "".join(secrets.choice(alphabet) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


def _recovery_hash(code: str) -> str:
    return sha256(code.replace("-", "").replace(" ", "").upper())


# ---------------------------------------------------------------- the service

class AuthService:
    def __init__(self, store: Store, config: Config | None = None, clock: Callable[[], float] = time.time):
        self.store = store
        self.config = config or Config()
        self.clock = clock
        # Each hash takes ~128 MiB at the default setting; capping how many run at
        # once keeps a burst of logins from exhausting memory.
        self._hash_slots = threading.BoundedSemaphore(self.config.max_concurrent_hashes)
        # Verifying against this when the username doesn't exist makes a failed
        # login cost the same time whether or not the account is real.
        self._dummy_hash = self._hash(secrets.token_urlsafe(16))

    # ------------------------------------------------ helpers

    def _hash(self, password: str) -> str:
        with self._hash_slots:
            return passwords.hash_password(password, self.config.hash_params)

    def _verify(self, password: str, encoded: str) -> bool:
        with self._hash_slots:
            return passwords.verify_password(password, encoded)

    def _audit(self, conn, event: str, user_id: int | None = None, ip: str | None = None, detail: str = "") -> None:
        conn.execute("INSERT INTO audit (ts, user_id, event, ip, detail) VALUES (?, ?, ?, ?, ?)",
                     (self.clock(), user_id, event, ip, detail))

    def _aead(self) -> AESGCM:
        if len(self.config.data_key) != 32:
            raise AuthError("Two-factor authentication needs a 32-byte data key in the configuration.")
        return AESGCM(self.config.data_key)

    def _encrypt(self, user_id: int, secret: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        # The user id is bound in as associated data: a ciphertext copied to
        # another user's row won't decrypt.
        return nonce + self._aead().encrypt(nonce, secret, str(user_id).encode())

    def _decrypt(self, user_id: int, blob: bytes) -> bytes:
        return self._aead().decrypt(blob[:12], blob[12:], str(user_id).encode())

    # ------------------------------------------------ accounts

    def register(self, username: str, email: str, password: str, ip: str | None = None) -> int:
        key = normalize_username(username)
        mail = normalize_email(email)
        if not (3 <= len(key) <= 32) or not all(ch.isalnum() or ch in "._-" for ch in key):
            raise AuthError("Username must be 3–32 letters, digits, '.', '_' or '-'.")
        if mail.count("@") != 1 or "." not in mail.split("@")[1] or len(mail) > 254:
            raise AuthError("That doesn't look like an e-mail address.")
        problems = passwords.check_policy(password, username=username, email=mail, service=self.config.issuer)
        if problems:
            raise PolicyError(problems)
        pw_hash = self._hash(password)   # slow: outside the transaction
        now = self.clock()
        with self.store.tx() as conn:
            if conn.execute("SELECT 1 FROM users WHERE username = ? OR email = ?", (key, mail)).fetchone():
                raise Conflict("That username or e-mail address is already registered.")
            user_id = conn.execute(
                "INSERT INTO users (username, display_name, email, password_hash, created_at, password_changed_at) "
                "VALUES (?, ?, ?, ?, ?, ?)", (key, username.strip(), mail, pw_hash, now, now)).lastrowid
            self._audit(conn, "register", user_id, ip)
        return user_id

    # ------------------------------------------------ login

    def _reserve_attempt(self, key: str, ip: str | None) -> None:
        """Count this attempt as a failure *before* checking the password.

        Checking first and counting afterwards is a race: fifty requests sent at
        once would all pass the "locked?" check before any of them recorded a
        failure, giving an attacker fifty guesses instead of five. Reserving the
        attempt inside one IMMEDIATE transaction means at most `lock_threshold`
        passwords are ever checked per lock period. A successful login gives the
        reservation back by clearing the counter.
        """
        now = self.clock()
        c = self.config
        with self.store.tx() as conn:
            if ip:
                conn.execute("DELETE FROM ip_failures WHERE ts < ?", (now - c.ip_window,))
                n_ip, oldest = conn.execute("SELECT COUNT(*), MIN(ts) FROM ip_failures WHERE ip = ?", (ip,)).fetchone()
                if n_ip >= c.ip_max_failures:
                    self._audit(conn, "login_blocked_ip", None, ip)
                    raise TooManyAttempts(oldest + c.ip_window - now)
            row = conn.execute("SELECT count, locked_until FROM login_failures WHERE username_key = ?", (key,)).fetchone()
            if row and row["locked_until"] > now:
                raise TooManyAttempts(row["locked_until"] - now)
            count = (row["count"] if row else 0) + 1
            locked_until = 0.0
            if count >= c.lock_threshold:
                locked_until = now + min(c.lock_base * 2 ** (count - c.lock_threshold), c.lock_max)
            conn.execute(
                "INSERT INTO login_failures (username_key, count, locked_until, last_failure) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(username_key) DO UPDATE SET count = excluded.count, "
                "locked_until = excluded.locked_until, last_failure = excluded.last_failure",
                (key, count, locked_until, now))
            if ip:
                conn.execute("INSERT INTO ip_failures (ip, ts) VALUES (?, ?)", (ip, now))

    def _release_attempt(self, conn, key: str, ip: str | None) -> None:
        conn.execute("DELETE FROM login_failures WHERE username_key = ?", (key,))
        if ip:
            # Remove the one reservation this attempt made for the IP.
            conn.execute("DELETE FROM ip_failures WHERE rowid = (SELECT rowid FROM ip_failures WHERE ip = ? "
                         "ORDER BY ts DESC LIMIT 1)", (ip,))

    def login(self, username: str, password: str, ip: str | None = None, user_agent: str = "") -> LoginResult:
        key = normalize_username(username)
        self._reserve_attempt(key, ip)
        with self.store.read() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (key,)).fetchone()
        stored = user["password_hash"] if user else self._dummy_hash
        ok = self._verify(password[:passwords.MAX_LENGTH * 4], stored) and user is not None
        if not ok:
            with self.store.tx() as conn:
                self._audit(conn, "login_failed", user["id"] if user else None, ip, "" if user else "unknown user")
            raise InvalidCredentials()

        with self.store.tx() as conn:
            self._release_attempt(conn, key, ip)
            if passwords.needs_rehash(user["password_hash"], self.config.hash_params):
                # The plain password is only available now, at login: upgrade the hash.
                conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                             (self._hash(password), user["id"]))
                self._audit(conn, "password_rehashed", user["id"], ip)
            if user["totp_secret"] is not None:
                token = secrets.token_urlsafe(32)
                conn.execute("INSERT INTO mfa_challenges (token_hash, user_id, created_at, ip, user_agent) "
                             "VALUES (?, ?, ?, ?, ?)", (sha256(token), user["id"], self.clock(), ip, user_agent))
                self._audit(conn, "login_password_ok_mfa_pending", user["id"], ip)
                return LoginResult(mfa_token=token)
            session = self._new_session(conn, user["id"], ip, user_agent)
            self._audit(conn, "login", user["id"], ip)
            return LoginResult(session=session)

    def login_mfa(self, mfa_token: str, code: str, ip: str | None = None) -> Session:
        """Second step: a TOTP code or one of the recovery codes."""
        now = self.clock()
        with self.store.tx() as conn:
            ch = conn.execute("SELECT * FROM mfa_challenges WHERE token_hash = ?", (sha256(mfa_token),)).fetchone()
            if ch is None or now - ch["created_at"] > self.config.mfa_ttl or ch["attempts"] >= self.config.mfa_max_attempts:
                if ch is not None:
                    conn.execute("DELETE FROM mfa_challenges WHERE token_hash = ?", (ch["token_hash"],))
                raise InvalidToken("This sign-in has expired. Start again with your password.")
            # Count the attempt first, for the same reason as passwords.
            conn.execute("UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token_hash = ?", (ch["token_hash"],))
            user = conn.execute("SELECT * FROM users WHERE id = ?", (ch["user_id"],)).fetchone()
            key = self._decrypt(user["id"], user["totp_secret"])
            step = totp.match_step(key, code, now)
            how = None
            if step is not None and (user["totp_last_step"] is None or step > user["totp_last_step"]):
                conn.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
                how = "totp"
            elif step is None:
                used = conn.execute("UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? "
                                    "AND used_at IS NULL", (now, user["id"], _recovery_hash(code))).rowcount
                how = "recovery_code" if used else None
            if how is None:
                self._audit(conn, "mfa_failed", user["id"], ip, "replayed code" if step is not None else "")
                failed = True
            else:
                failed = False
                conn.execute("DELETE FROM mfa_challenges WHERE token_hash = ?", (ch["token_hash"],))
                session = self._new_session(conn, user["id"], ch["ip"], ch["user_agent"])
                self._audit(conn, "login", user["id"], ip, f"second factor: {how}")
        if failed:   # raised after the transaction commits, so the attempt stays counted
            raise InvalidCredentials("That code isn't right.")
        return session

    # ------------------------------------------------ sessions

    def _new_session(self, conn, user_id: int, ip: str | None, user_agent: str) -> Session:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        public_id = secrets.token_hex(6)
        now = self.clock()
        conn.execute("INSERT INTO sessions (token_hash, public_id, user_id, csrf_hash, created_at, last_seen, ip, user_agent) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (sha256(token), public_id, user_id, sha256(csrf), now, now, ip, (user_agent or "")[:200]))
        return Session(token, csrf, public_id, user_id)

    def authenticate(self, token: str | None) -> dict | None:
        """The session for a cookie value, or None if missing, unknown or expired."""
        if not token:
            return None
        now = self.clock()
        th = sha256(token)
        with self.store.tx() as conn:
            row = conn.execute("SELECT s.*, u.display_name, u.email FROM sessions s JOIN users u ON u.id = s.user_id "
                               "WHERE s.token_hash = ?", (th,)).fetchone()
            if row is None:
                return None
            if now - row["last_seen"] > self.config.session_idle or now - row["created_at"] > self.config.session_absolute:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
                self._audit(conn, "session_expired", row["user_id"])
                return None
            if now - row["last_seen"] >= self.config.touch_interval:
                conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, th))
            return dict(row)

    def check_csrf(self, session: dict, header_value: str | None) -> bool:
        return bool(header_value) and hmac.compare_digest(sha256(header_value), session["csrf_hash"])

    def logout(self, token: str) -> None:
        with self.store.tx() as conn:
            row = conn.execute("DELETE FROM sessions WHERE token_hash = ? RETURNING user_id", (sha256(token),)).fetchone()
            if row:
                self._audit(conn, "logout", row["user_id"])

    def logout_everywhere(self, user_id: int) -> int:
        with self.store.tx() as conn:
            n = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,)).rowcount
            self._audit(conn, "logout_everywhere", user_id, detail=f"{n} sessions")
        return n

    def list_sessions(self, user_id: int) -> list[dict]:
        with self.store.read() as conn:
            rows = conn.execute("SELECT public_id, created_at, last_seen, ip, user_agent FROM sessions "
                                "WHERE user_id = ? ORDER BY last_seen DESC", (user_id,)).fetchall()
        return [dict(r) for r in rows]

    def revoke_session(self, user_id: int, public_id: str) -> bool:
        with self.store.tx() as conn:
            # The user_id condition stops one user from revoking another's session.
            n = conn.execute("DELETE FROM sessions WHERE user_id = ? AND public_id = ?", (user_id, public_id)).rowcount
            if n:
                self._audit(conn, "session_revoked", user_id, detail=public_id)
        return bool(n)

    # ------------------------------------------------ passwords

    def change_password(self, user_id: int, current: str, new: str, ip: str | None = None, user_agent: str = "") -> Session:
        """Verify the current password, set the new one, and replace *every*
        session (including this one) with a single new session."""
        with self.store.read() as conn:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        key = user["username"]
        self._reserve_attempt(key, ip)   # a stolen session mustn't allow unlimited password guessing
        if not self._verify(current, user["password_hash"]):
            with self.store.tx() as conn:
                self._audit(conn, "password_change_failed", user_id, ip)
            raise InvalidCredentials()
        problems = passwords.check_policy(new, username=user["display_name"], email=user["email"], service=self.config.issuer)
        if problems:
            with self.store.tx() as conn:
                self._release_attempt(conn, key, ip)
            raise PolicyError(problems)
        new_hash = self._hash(new)
        with self.store.tx() as conn:
            self._release_attempt(conn, key, ip)
            conn.execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
                         (new_hash, self.clock(), user_id))
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user_id,))
            session = self._new_session(conn, user_id, ip, user_agent)
            self._audit(conn, "password_changed", user_id, ip)
        return session

    def request_reset(self, email: str, ip: str | None = None) -> None:
        """Queue a reset e-mail if the address belongs to an account. The caller
        gets the same answer either way, and both paths do one write."""
        mail = normalize_email(email)
        now = self.clock()
        with self.store.tx() as conn:
            user = conn.execute("SELECT id, email FROM users WHERE email = ?", (mail,)).fetchone()
            if user is None:
                self._audit(conn, "reset_requested_unknown", None, ip)
                return
            token = secrets.token_urlsafe(32)
            conn.execute("INSERT INTO reset_tokens (token_hash, user_id, created_at) VALUES (?, ?, ?)",
                         (sha256(token), user["id"], now))
            conn.execute("INSERT INTO outbox (to_addr, subject, body, created_at) VALUES (?, ?, ?, ?)",
                         (user["email"], "Reset your password",
                          f"Someone asked to reset your password. If it was you, open this link within "
                          f"{int(self.config.reset_ttl // 60)} minutes:\n{self.config.reset_url}{token}\n"
                          "If it wasn't you, ignore this e-mail; your password hasn't changed.", now))
            self._audit(conn, "reset_requested", user["id"], ip)

    def reset_password(self, token: str, new: str, ip: str | None = None) -> None:
        now = self.clock()
        th = sha256(token or "")
        with self.store.read() as conn:
            row = conn.execute("SELECT r.*, u.display_name, u.email FROM reset_tokens r JOIN users u ON u.id = r.user_id "
                               "WHERE r.token_hash = ?", (th,)).fetchone()
        if row is None or row["used_at"] is not None or now - row["created_at"] > self.config.reset_ttl:
            raise InvalidToken("This reset link is invalid or has expired. Ask for a new one.")
        problems = passwords.check_policy(new, username=row["display_name"], email=row["email"], service=self.config.issuer)
        if problems:
            raise PolicyError(problems)
        new_hash = self._hash(new)
        with self.store.tx() as conn:
            # Claim the token atomically: if two requests race, only one sees used_at IS NULL.
            claimed = conn.execute("UPDATE reset_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
                                   (now, th)).rowcount
            if not claimed:
                raise InvalidToken("This reset link is invalid or has expired. Ask for a new one.")
            conn.execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
                         (new_hash, now, row["user_id"]))
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ? AND token_hash != ?", (row["user_id"], th))
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (row["user_id"],))
            user = conn.execute("SELECT username FROM users WHERE id = ?", (row["user_id"],)).fetchone()
            conn.execute("DELETE FROM login_failures WHERE username_key = ?", (user["username"],))
            self._audit(conn, "password_reset", row["user_id"], ip)

    # ------------------------------------------------ two-factor authentication

    def mfa_begin(self, user_id: int) -> dict:
        key = totp.new_secret()
        with self.store.tx() as conn:
            user = conn.execute("SELECT username, totp_secret FROM users WHERE id = ?", (user_id,)).fetchone()
            if user["totp_secret"] is not None:
                raise Conflict("Two-factor authentication is already on.")
            conn.execute("UPDATE users SET totp_pending = ? WHERE id = ?", (self._encrypt(user_id, key), user_id))
        return {"secret": totp.to_base32(key),
                "otpauth_uri": totp.provisioning_uri(key, user["username"], self.config.issuer)}

    def mfa_confirm(self, user_id: int, code: str) -> list[str]:
        """Turn 2FA on once the user proves their app has the secret. Returns the
        recovery codes; they are shown once and stored only as hashes."""
        now = self.clock()
        with self.store.tx() as conn:
            user = conn.execute("SELECT totp_pending FROM users WHERE id = ?", (user_id,)).fetchone()
            if user["totp_pending"] is None:
                raise AuthError("Start two-factor setup first.")
            key = self._decrypt(user_id, user["totp_pending"])
            step = totp.match_step(key, code, now)
            if step is None:
                raise InvalidCredentials("That code isn't right. Check the time on your phone.")
            codes = [_recovery_code() for _ in range(self.config.recovery_codes)]
            conn.execute("UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ? "
                         "WHERE id = ?", (step, user_id))
            conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
            conn.executemany("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                             [(user_id, _recovery_hash(c)) for c in codes])
            self._audit(conn, "mfa_enabled", user_id)
        return codes

    def mfa_disable(self, user_id: int, password: str, ip: str | None = None) -> None:
        with self.store.read() as conn:
            user = conn.execute("SELECT username, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        self._reserve_attempt(user["username"], ip)
        if not self._verify(password, user["password_hash"]):
            raise InvalidCredentials()
        with self.store.tx() as conn:
            self._release_attempt(conn, user["username"], ip)
            conn.execute("UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL WHERE id = ?",
                         (user_id,))
            conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
            self._audit(conn, "mfa_disabled", user_id, ip)
