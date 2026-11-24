"""Password hashing with scrypt, and a password policy following NIST SP 800-63B.

Hashes are stored as self-describing strings, so parameters can be raised
later without breaking existing accounts:

    $scrypt$ln=17,r=8,p=1$<salt, base64>$<hash, base64>

`ln` is log2(N). On a successful login, `needs_rehash()` tells the caller
whether the stored hash uses weaker parameters than the current ones; if so
the password (which the server has in hand at that moment) is hashed again.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScryptParams:
    """scrypt cost parameters. Memory used is 128 * r * 2**ln bytes (128 MiB for the default)."""

    ln: int = 17      # N = 2**17: OWASP's minimum recommendation for scrypt
    r: int = 8
    p: int = 1
    salt_bytes: int = 16
    hash_bytes: int = 32

    @property
    def memory(self) -> int:
        return 128 * self.r * (2 ** self.ln) * self.p


DEFAULT = ScryptParams()
_FORMAT = re.compile(r"^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/]+={0,2})\$([A-Za-z0-9+/]+={0,2})$")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _derive(password: str, salt: bytes, ln: int, r: int, p: int, length: int) -> bytes:
    # OpenSSL refuses to allocate more than `maxmem` (32 MiB by default); allow the
    # parameters' real requirement plus slack.
    maxmem = 128 * r * (2 ** ln) * p + 2 * 1024 * 1024 + 256 * r * p
    return hashlib.scrypt(normalize_password(password).encode("utf-8"), salt=salt,
                          n=2 ** ln, r=r, p=p, dklen=length, maxmem=maxmem)


def normalize_password(password: str) -> str:
    """NFKC-normalise, as SP 800-63B recommends, so that the same password typed
    on different keyboards or OSes (composed vs decomposed accents) still matches."""
    return unicodedata.normalize("NFKC", password)


def hash_password(password: str, params: ScryptParams = DEFAULT) -> str:
    salt = os.urandom(params.salt_bytes)
    digest = _derive(password, salt, params.ln, params.r, params.p, params.hash_bytes)
    return f"$scrypt$ln={params.ln},r={params.r},p={params.p}${_b64(salt)}${_b64(digest)}"


def parse(encoded: str) -> tuple[int, int, int, bytes, bytes]:
    m = _FORMAT.match(encoded)
    if not m:
        raise ValueError("not a $scrypt$ hash")
    ln, r, p = int(m[1]), int(m[2]), int(m[3])
    if not (1 <= ln <= 24 and 1 <= r <= 32 and 1 <= p <= 16):
        raise ValueError("scrypt parameters out of range")
    return ln, r, p, base64.b64decode(m[4]), base64.b64decode(m[5])


def verify_password(password: str, encoded: str) -> bool:
    """True if `password` matches. The comparison is constant-time."""
    ln, r, p, salt, expected = parse(encoded)
    actual = _derive(password, salt, ln, r, p, len(expected))
    return hmac.compare_digest(actual, expected)


def needs_rehash(encoded: str, params: ScryptParams = DEFAULT) -> bool:
    ln, r, p, salt, digest = parse(encoded)
    return (ln, r, p) < (params.ln, params.r, params.p) or len(digest) < params.hash_bytes or len(salt) < params.salt_bytes


# ---------------------------------------------------------------- policy

MIN_LENGTH = 12
MAX_LENGTH = 128   # long enough for passphrases; bounds the hashing work per request

_COMMON_FILE = Path(__file__).with_name("common_passwords.txt")


def _load_common() -> frozenset[str]:
    words = set()
    for line in _COMMON_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.add(line.casefold())
    return frozenset(words)


COMMON = _load_common()


def _squash(text: str) -> str:
    """Lower-case and drop everything but letters and digits: 'Pass-Word 2024!' -> 'password2024'."""
    return "".join(ch for ch in unicodedata.normalize("NFKC", text).casefold() if ch.isalnum())


def check_policy(password: str, *, username: str = "", email: str = "", service: str = "authsvc") -> list[str]:
    """Problems with a new password; an empty list means it's acceptable.

    SP 800-63B: require length, allow everything (spaces, emoji, any Unicode),
    no composition rules ("one uppercase, one symbol..."), but reject passwords
    that are known to be common or that are built from context the attacker knows.
    """
    problems = []
    pw = normalize_password(password)
    if len(pw) < MIN_LENGTH:
        problems.append(f"must be at least {MIN_LENGTH} characters")
    if len(pw) > MAX_LENGTH:
        problems.append(f"must be at most {MAX_LENGTH} characters")
    if any(unicodedata.category(ch) == "Cc" for ch in pw):
        problems.append("must not contain control characters")
    squashed = _squash(pw)
    if pw.casefold() in COMMON or squashed in COMMON or squashed.rstrip("0123456789") in COMMON:
        problems.append("is a commonly used password")
    if squashed and len(set(squashed)) <= 2:
        problems.append("is too repetitive")
    context = [_squash(w) for w in (username, email.split("@")[0], service) if w]
    if any(c and len(c) >= 4 and c in squashed for c in context):
        problems.append("must not contain your username, email or the service name")
    return problems
