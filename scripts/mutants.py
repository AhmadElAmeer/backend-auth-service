"""Planted-bug check: apply one security bug at a time, run the test suite,
and report whether it failed. Source files are restored after each run.

    python scripts/mutants.py          all
    python scripts/mutants.py 3 11     only mutants 3 and 11
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P, T, S, W = "authsvc/passwords.py", "authsvc/totp.py", "authsvc/service.py", "authsvc/web.py"

CHECK_THEN_COUNT = (
    """        self._reserve_attempt(key, ip)
        with self.store.read() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (key,)).fetchone()""",
    """        with self.store.read() as conn:
            r0 = conn.execute("SELECT locked_until FROM login_failures WHERE username_key = ?", (key,)).fetchone()
            user = conn.execute("SELECT * FROM users WHERE username = ?", (key,)).fetchone()
        if r0 and r0[0] > self.clock():
            raise TooManyAttempts(r0[0] - self.clock())""")
COUNT_AFTER = (
    """                self._audit(conn, "login_failed", user["id"] if user else None, ip, "" if user else "unknown user")
            raise InvalidCredentials()""",
    """                self._audit(conn, "login_failed", user["id"] if user else None, ip, "" if user else "unknown user")
            self._reserve_attempt(key, ip)
            raise InvalidCredentials()""")

# (name, [(file, old, new), ...])
MUTANTS = [
    # passwords
    ("fixed salt", [(P, "salt = os.urandom(params.salt_bytes)", "salt = bytes(params.salt_bytes)")]),
    ("no Unicode normalisation", [(P, 'return unicodedata.normalize("NFKC", password)', "return password")]),
    ("never rehash", [(S, "if passwords.needs_rehash(user[\"password_hash\"], self.config.hash_params):", "if False:")]),
    ("common-password check off", [(P, "if pw.casefold() in COMMON or squashed in COMMON or squashed.rstrip(\"0123456789\") in COMMON:",
                                    "if pw.casefold() in COMMON:")]),
    ("username allowed in the password", [(P, "if any(c and len(c) >= 4 and c in squashed for c in context):", "if False:")]),
    ("minimum length 8", [(P, "MIN_LENGTH = 12", "MIN_LENGTH = 8")]),
    # totp
    ("TOTP: wrong dynamic truncation", [(T, "offset = mac[-1] & 0x0F", "offset = mac[0] & 0x0F")]),
    ("TOTP: no drift window", [(T, "for s in range(now - window, now + window + 1):", "for s in range(now, now + 1):")]),
    ("TOTP: Unicode digits crash compare_digest", [(T, "not (code.isascii() and code.isdigit())", "not code.isdigit()")]),
    ("TOTP: codes can be replayed", [(S, "(user[\"totp_last_step\"] is None or step > user[\"totp_last_step\"])", "True")]),
    # login throttling
    ("check-then-count race", [(S, *CHECK_THEN_COUNT), (S, *COUNT_AFTER)]),
    ("lock one attempt late", [(S, "if count >= c.lock_threshold:", "if count > c.lock_threshold:")]),
    ("no 15-minute cap on the lock", [(S, "min(c.lock_base * 2 ** (count - c.lock_threshold), c.lock_max)",
                                       "c.lock_base * 2 ** (count - c.lock_threshold)")]),
    ("success doesn't reset the counter", [(S, '        conn.execute("DELETE FROM login_failures WHERE username_key = ?", (key,))\n        if ip:',
                                            "        if ip:")]),
    ("IP limit off by one", [(S, "if n_ip >= c.ip_max_failures:", "if n_ip > c.ip_max_failures:")]),
    ("unknown user skips hashing (timing leak)", [(S, "ok = self._verify(password[:passwords.MAX_LENGTH * 4], stored) and user is not None",
                                                    "ok = user is not None and self._verify(password[:passwords.MAX_LENGTH * 4], stored)")]),
    ("unknown user gets a different error", [(S, "            raise InvalidCredentials()\n\n        with self.store.tx() as conn:\n            self._release_attempt",
                                              "            raise InvalidCredentials() if user else AuthError('No such user.')\n\n        with self.store.tx() as conn:\n            self._release_attempt")]),
    ("no limit on concurrent hashes", [(S, "threading.BoundedSemaphore(self.config.max_concurrent_hashes)", "threading.BoundedSemaphore(10 ** 6)")]),
    # sessions
    ("no idle timeout", [(S, 'if now - row["last_seen"] > self.config.session_idle or ', "if ")]),
    ("no absolute timeout", [(S, ' or now - row["created_at"] > self.config.session_absolute:', ":")]),
    ("session tokens stored in plain text", [(S, "(sha256(token), public_id, user_id, sha256(csrf)", "(token, public_id, user_id, sha256(csrf)"),
                                             (S, "        th = sha256(token)\n        with self.store.tx() as conn:\n            row = conn.execute(\"SELECT s.*",
                                              "        th = token\n        with self.store.tx() as conn:\n            row = conn.execute(\"SELECT s.*")]),
    ("logout doesn't end the session", [(S, '"DELETE FROM sessions WHERE token_hash = ? RETURNING user_id"', '"SELECT user_id FROM sessions WHERE token_hash = ?"')]),
    ("revoke any user's session", [(S, '"DELETE FROM sessions WHERE user_id = ? AND public_id = ?", (user_id, public_id)',
                                    '"DELETE FROM sessions WHERE public_id = ?", (public_id,)')]),
    ("password change keeps other sessions", [(S, """            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user_id,))""",
                                               """            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user_id,))""")]),
    ("password change keeps reset links", [(S, """            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user_id,))
            session = self._new_session""", """            session = self._new_session""")]),
    # web
    ("CSRF token not checked", [(S, 'return bool(header_value) and hmac.compare_digest(sha256(header_value), session["csrf_hash"])', "return True")]),
    ("Origin not checked", [(W, "if request.method in UNSAFE and origin is not None and origin not in origins:", "if False:")]),
    ("cookie readable by JavaScript", [(W, "httponly=True, secure=True, samesite=\"Lax\", path=\"/\",\n", "httponly=False, secure=True, samesite=\"Lax\", path=\"/\",\n")]),
    ("responses cacheable", [(W, 'resp.headers["Cache-Control"] = "no-store"', 'resp.headers["Cache-Control"] = "private"')]),
    # reset
    ("reset links never expire", [(S, ' or now - row["created_at"] > self.config.reset_ttl:', ":")]),
    ("reset links reusable", [(S, 'if row is None or row["used_at"] is not None or', "if row is None or"),
                              (S, "WHERE token_hash = ? AND used_at IS NULL\",\n", "WHERE token_hash = ?\",\n")]),
    ("reset claim not atomic (race)", [(S, "WHERE token_hash = ? AND used_at IS NULL\",\n", "WHERE token_hash = ?\",\n")]),
    ("reset keeps sessions", [(S, '            conn.execute("DELETE FROM sessions WHERE user_id = ?", (row["user_id"],))\n', "")]),
    ("forgot-password reveals unknown addresses", [(S, """                self._audit(conn, "reset_requested_unknown", None, ip)
                return""", """                raise AuthError("No account with that address.")""")]),
    # mfa
    ("recovery codes reusable", [(S, '"AND used_at IS NULL", (now, user["id"], _recovery_hash(code))', '"", (now, user["id"], _recovery_hash(code))')]),
    ("unlimited MFA attempts", [(S, ' or ch["attempts"] >= self.config.mfa_max_attempts:', ":")]),
    ("MFA challenge never expires", [(S, ' or now - ch["created_at"] > self.config.mfa_ttl', "")]),
    ("TOTP key not bound to the user", [(S, "nonce + self._aead().encrypt(nonce, secret, str(user_id).encode())", "nonce + self._aead().encrypt(nonce, secret, b\"\")"),
                                        (S, "self._aead().decrypt(blob[:12], blob[12:], str(user_id).encode())", "self._aead().decrypt(blob[:12], blob[12:], b\"\")")]),
]


def main() -> int:
    only = {int(a) for a in sys.argv[1:]}
    # Validate every pattern first.
    for i, (name, edits) in enumerate(MUTANTS, 1):
        for file, old, _ in edits:
            n = (ROOT / file).read_text().count(old)
            if n != 1:
                raise SystemExit(f"mutant {i} ({name}): pattern found {n} times in {file}")
    caught = ran = 0
    for i, (name, edits) in enumerate(MUTANTS, 1):
        if only and i not in only:
            continue
        originals = {f: (ROOT / f).read_text() for f, _, _ in edits}
        try:
            for file, old, new in edits:
                path = ROOT / file
                path.write_text(path.read_text().replace(old, new))
            t = time.time()
            r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
                               cwd=ROOT, capture_output=True, text=True)
            failed = r.returncode != 0
            first = next((line for line in r.stdout.splitlines() if line.startswith("FAILED")), "")
            ran += 1
            caught += failed
            print(f"{i:2}. {'CAUGHT' if failed else 'MISSED'}  {name} ({time.time() - t:.0f} s)"
                  + (f"\n      {first[:150]}" if first else ""), flush=True)
        finally:
            for f, text in originals.items():
                (ROOT / f).write_text(text)
    print(f"\n{caught}/{ran} planted bugs caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
