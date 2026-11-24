"""One-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238), as used by
authenticator apps such as Google Authenticator, Aegis or 1Password.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote, urlencode


def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "sha1") -> str:
    """RFC 4226 §5.3: HMAC the 8-byte counter, dynamically truncate, take the last `digits` digits."""
    mac = hmac.new(key, struct.pack(">Q", counter), algorithm).digest()
    offset = mac[-1] & 0x0F
    code = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)


def totp(key: bytes, unix_time: float, step: int = 30, digits: int = 6, algorithm: str = "sha1", t0: int = 0) -> str:
    """RFC 6238: HOTP with counter = floor((time - T0) / step)."""
    return hotp(key, int((unix_time - t0) // step), digits, algorithm)


def new_secret(n_bytes: int = 20) -> bytes:
    """160 bits, the size RFC 4226 recommends for HMAC-SHA1."""
    return secrets.token_bytes(n_bytes)


def to_base32(key: bytes) -> str:
    """The form users type into an app: base32 without padding."""
    return base64.b32encode(key).decode("ascii").rstrip("=")


def from_base32(text: str) -> bytes:
    cleaned = text.replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def provisioning_uri(key: bytes, account: str, issuer: str) -> str:
    """The otpauth:// URI that authenticator apps read from a QR code."""
    label = quote(f"{issuer}:{account}", safe=":@")
    query = urlencode({"secret": to_base32(key), "issuer": issuer, "algorithm": "SHA1", "digits": 6, "period": 30})
    return f"otpauth://totp/{label}?{query}"


def match_step(key: bytes, code: str, unix_time: float, *, window: int = 1, step: int = 30, digits: int = 6) -> int | None:
    """The time step whose code equals `code`, checking `window` steps either side
    of now (clocks drift and people type slowly), or None.

    Returning the step lets the caller reject a code that was already used:
    a TOTP code is otherwise valid for up to (2 * window + 1) * step seconds.
    """
    code = code.strip().replace(" ", "")
    # isascii() matters: str.isdigit() accepts full-width and other Unicode
    # digits, and hmac.compare_digest raises on non-ASCII strings.
    if len(code) != digits or not (code.isascii() and code.isdigit()):
        return None
    now = int(unix_time // step)
    found = None
    # Check every candidate (no early exit) so timing doesn't reveal which step matched.
    for s in range(now - window, now + window + 1):
        if hmac.compare_digest(hotp(key, s, digits), code) and found is None:
            found = s
    return found
