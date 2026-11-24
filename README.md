# backend-auth-service

[![CI](https://github.com/AhmadElAmeer/backend-auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/AhmadElAmeer/backend-auth-service/actions/workflows/ci.yml)

An authentication service in Python (Flask and SQLite) that handles the parts most often done wrong:
- password hashing with scrypt;
- server-side sessions with CSRF protection;
- login throttling that can't be raced;
- password resets;
- TOTP two-factor authentication.

Every security property has a test that attacks it, and 38 planted security bugs are all caught by those tests.

## Problem

"Add a login page" sounds small. Done carelessly, it leaks in ways nobody notices until an incident:

| What goes wrong | Consequence |
|---|---|
| A fast hash (or no hash) | A leaked database becomes a leaked password list. |
| "No such user" vs "wrong password" | Attackers learn which accounts exist. |
| Lockout checked before the attempt is counted | Fifty simultaneous guesses all get checked. |
| Reset links that never expire, or work twice | Old e-mails become keys to the account. |
| TOTP codes accepted again within their 30 seconds | A shoulder-surfed or phished code can be reused. |

None of these show up in a happy-path test. This project implements the whole flow and tests each of these failure modes directly.

## Overview

| Area | What it does |
|---|---|
| **Passwords** | scrypt with OWASP's minimum parameters (N=2^17, r=8, p=1: 128 MiB, ~290 ms here), random salt, self-describing hash strings, transparent re-hashing when parameters rise; NIST SP 800-63B policy: length ≥ 12, any Unicode, no composition rules, but common and context-derived passwords refused |
| **Login** | identical answer and timing for unknown users; per-username lockout that doubles from 1 s to 15 min; per-IP limit; attempts counted *before* the password is checked, so concurrency can't beat the limit; at most 4 hashes at once |
| **Sessions** | 256-bit random tokens in a `__Host-` cookie (HttpOnly, Secure, SameSite=Lax), stored only as SHA-256; new token at every login; 30-minute idle and 12-hour absolute expiry; list and revoke your sessions; "log out everywhere" |
| **CSRF** | per-session token required in a header on every state-changing request, plus an Origin check |
| **Reset** | single-use 30-minute links stored hashed, claimed atomically; same answer for unknown addresses; a reset ends all sessions and clears lockouts but does *not* bypass 2FA |
| **2FA** | TOTP (RFC 6238) with ±30 s drift, replay protection, encrypted secrets (AES-GCM, bound to the user), 10 single-use recovery codes, attempts limited per challenge |
| **Audit** | every security event is recorded (login, failure, lock, reset, 2FA changes) |

## Key results

**Online guessing** ([`scripts/attack_sim.py`](scripts/attack_sim.py)) runs the real service with a simulated clock. The attacker sends 20 requests a second and waits exactly as long as `Retry-After` says:

| policy | guesses checked in 1 hour | in 24 hours | longest lock |
|---|---:|---:|---:|
| no throttling | 72,000 | 1,728,000 | – |
| this service, one IP | 17 | 109 | 900 s |
| this service, a new IP for every request | 17 | 109 | 900 s |

The lock belongs to the username, not the IP, so rotating IPs doesn't help against one account. *Password spraying* (one common password tried against many usernames) is capped by the per-IP limit: 400 guesses an hour from one IP. That's why the policy also refuses common passwords.

**Hashing cost** ([`docs/bench.txt`](docs/bench.txt), `python scripts/bench_hash.py`), measured on a 2-core x86-64 VM with Python 3.13:

| scrypt setting | memory | verify (median) | guesses/s per core |
|---|---:|---:|---:|
| N=2^14, r=8 | 16 MiB | 30 ms | 32.8 |
| N=2^15, r=8 | 32 MiB | 63 ms | 16.0 |
| N=2^16, r=8 | 64 MiB | 148 ms | 6.7 |
| **N=2^17, r=8 (default)** | **128 MiB** | **292 ms** | **3.4** |

Measured through the HTTP API, a failed login takes 295 ms for a real user and 293 ms for an unknown one. Both run scrypt once, so timing doesn't reveal which accounts exist; a test checks this. The 128 MiB per hash is also why concurrent hashing is capped: an unbounded burst of logins could exhaust the server's memory.

## Tech stack

- Python 3.11+.
- Flask for the JSON API, SQLite (WAL mode) for storage.
- `hashlib.scrypt` (OpenSSL), and `cryptography` for AES-GCM.
- pytest; GitHub Actions on Python 3.11–3.13.

## Architecture

```
authsvc/
  passwords.py   scrypt hash/verify/needs_rehash; SP 800-63B policy
  common_passwords.txt
  totp.py        HOTP (RFC 4226), TOTP (RFC 6238), base32, otpauth:// URIs, windowed matching
  store.py       SQLite schema; one short transaction per operation (BEGIN IMMEDIATE for read-check-write)
  service.py     AuthService: register, login (+ throttling), MFA, sessions, password change, reset
  web.py         Flask app: routes, cookie, CSRF and Origin checks, security headers
tests/           RFC vectors, a pure-Python scrypt oracle, attack and race tests (97 tests)
scripts/         attack_sim.py, bench_hash.py, demo.py, mutants.py
```

The service knows nothing about HTTP, and time comes from an injected clock. Tests can therefore jump 15 minutes ahead instead of sleeping, and the attack simulation runs a day of attacks in a few seconds.

**A login, step by step:**

1. Normalise the username (NFKC, case-fold).
2. **Reserve the attempt.** In one `BEGIN IMMEDIATE` transaction:
   - refuse if this IP has too many recent failures, or if this username is locked;
   - otherwise increment the failure count and set the next lock if it reaches 5.
3. Verify the password with scrypt. If the user doesn't exist, verify against a dummy hash, so it costs the same.
4. **On failure:** keep the reservation and return the generic 401.
5. **On success:**
   - release the reservation;
   - re-hash the password if its parameters are outdated;
   - if 2FA is on, return a short-lived challenge token; otherwise create a session.

Step 2 is the important one. Checking the lock and counting failures *after* the password check is a race: fifty concurrent requests all see "not locked" before any of them records a failure. A test fires 50 guesses through a barrier and requires exactly 5 password checks.

## Installation

```bash
git clone https://github.com/AhmadElAmeer/backend-auth-service
cd backend-auth-service
python -m pip install -r requirements.txt pytest
```

## Usage

```bash
export AUTH_DATA_KEY=$(python -c "import os; print(os.urandom(32).hex())")   # encrypts TOTP secrets; keep it out of the database
export AUTH_DB=auth.db
python -m authsvc.web                    # development server on :5000
```

The session cookie is `Secure` and `__Host-`-prefixed, so browsers only keep it over HTTPS. In production, run behind a TLS-terminating proxy, and pass `trust_proxy=True` to `create_app` only if that proxy sets `X-Forwarded-For`.

| endpoint | purpose |
|---|---|
| `POST /register` | `{username, email, password}` |
| `POST /login` | `{username, password}` → session cookie + `csrf_token`, or `{mfa_required, mfa_token}` |
| `POST /login/mfa` | `{mfa_token, code}`: a TOTP code or a recovery code |
| `GET /me`, `GET /sessions`, `DELETE /sessions/<id>` | who am I; my sessions; end one |
| `POST /logout`, `POST /logout-all` | end this session, or all of them |
| `POST /password/change` | `{current_password, new_password}`: replaces every session |
| `POST /password/forgot`, `POST /password/reset` | `{email}`; `{token, new_password}` |
| `POST /mfa/setup`, `/mfa/confirm`, `/mfa/disable` | start enrolment; confirm with a code (returns recovery codes); turn off with the password |

Every request that changes something while you're logged in needs the header `X-CSRF-Token: <csrf_token from login>`.

## Demo

`python scripts/demo.py` runs the whole flow against a temporary database and prints each exchange. Here is an abridged run ([full output](docs/demo.txt)):

```
POST /register {"username": "ahmad", ..., "password": "Password2024!"}
  → 400 {"error": "weak_password", "message": "Password is a commonly used password.", ...}
POST /login {"username": "ahmad", "password": "wrong guess"}
  → 401 {"error": "invalid_credentials", "message": "Incorrect username or password."}
POST /login {"username": "nobody", "password": "wrong guess"}
  → 401 {"error": "invalid_credentials", "message": "Incorrect username or password."}
(without the X-CSRF-Token header:)
POST /mfa/setup
  → 403 {"error": "csrf", "message": "Missing or wrong CSRF token."}
POST /login {"username": "ahmad", "password": "plum tractor violet 1987"}
  → 200 {"mfa_required": true, "mfa_token": "…"}
POST /password/forgot {"email": "someone@else.example"}
  → 202 {"message": "If that address has an account, we've sent a reset link."}
POST /password/reset {"token": "…", "new_password": "another good passphrase 9"}     (second use)
  → 400 {"error": "invalid_token", "message": "This reset link is invalid or has expired. Ask for a new one."}
(five wrong passwords later)
POST /login {"username": "ahmad", "password": "marble lantern quietly 2031"}
  → 429  Retry-After: 1 {"error": "too_many_attempts", ...}
```

## Testing

```bash
python -m pytest -q              # 97 tests, about 4 s
python scripts/mutants.py        # 38 planted bugs, about 2 minutes
```

- **Standards, with independent oracles:**
  - **scrypt:** all three RFC 7914 vectors run through `hashlib.scrypt`. A pure-Python scrypt written from the RFC ([`tests/scrypt_reference.py`](tests/scrypt_reference.py)) matches vector 1 and agrees with OpenSSL on 25 random inputs. The stored hash is checked against it too.
  - **One-time codes:** all 10 HOTP values from RFC 4226 and all 18 TOTP values from RFC 6238 (SHA-1, SHA-256, SHA-512).
- **Attacks:**
  - 50 concurrent guesses: exactly 5 checked.
  - Lockout progression 1 s → 2 s → … → 900 s, identical for real and made-up usernames.
  - Identical errors, and timing within 25% for unknown users (measured: 28.8 ms against 29.2 ms at N=2^14).
  - Per-IP limit with a sliding window.
  - TOTP replay and old codes refused.
  - Racing 8 resets with one token: exactly one wins.
  - Session fixation, CSRF (missing, wrong, or another session's token), cross-site Origin.
  - SQL-injection strings, 500 fuzzed request bodies (never a 500 response), oversized bodies.
- **Lifecycle:**
  - idle and absolute expiry at the exact boundary;
  - tokens never stored in plain text (checked against a full database dump);
  - password change ends every session and every reset link;
  - a reset doesn't bypass 2FA;
  - a TOTP secret copied to another user's row won't decrypt.
- **Planted bugs:** 38 security bugs planted one at a time across hashing, policy, TOTP, throttling, sessions, CSRF, cookies, resets and 2FA. **All 38 are caught**, including:
  - the check-then-count race;
  - skipping the dummy hash for unknown users (caught by the timing test);
  - a non-atomic reset claim (caught by the race test).

**Bugs the tests found while building:**
1. **A full-width TOTP code crashed the login.** `"１２３４５６".isdigit()` is true in Python, and `hmac.compare_digest` raises on non-ASCII strings, so this would have been a 500 error. Now `isascii()` is checked first.
2. **An off-by-one in the absolute timeout test:** my expectation was wrong, not the code. A session is valid *at* exactly 12:00:00 and expires one second later. The test now checks both sides of the boundary.

## Technical challenges and design decisions

- **Reserve, then verify.** Counting the attempt before checking the password is the simplest way to make throttling race-free. A successful login gives the reservation back. The cost is a write on every login, which SQLite in WAL mode handles easily at this scale.
- **Lock the username, not the account.** Failure counters are keyed by the normalised username *whether or not it exists*. Otherwise "this name gets locked, that one never does" would reveal which accounts are real. The same reasoning gives the dummy hash for unknown users, and the identical answer from "forgot password".
- **Exponential lock instead of a hard lockout.** Locking an account for good after 5 failures lets anyone lock anyone out. Doubling from 1 s up to a 15-minute cap holds an online attacker to about 100 guesses a day against one account, and a legitimate user waits at most 15 minutes (or uses a reset link, which clears the lock).
- **Registration still reveals taken usernames.** That's an accepted trade-off: hiding it would mean e-mail-only sign-up flows. The per-IP limit slows bulk probing.
- **Hash tokens, encrypt secrets.** Session, reset and challenge tokens are 256-bit random values, so a plain SHA-256 is enough and lookups stay indexable. TOTP keys must be recoverable to compute codes, so they are encrypted with AES-GCM under a key kept outside the database. The user id is bound in as associated data.
- **Don't trust `X-Forwarded-For` by default.** Any client can send that header. It is only used when `trust_proxy=True`, and then only its last entry, which your own proxy appended.

## Future improvements

- Check new passwords against the Have I Been Pwned breach corpus with its k-anonymity range API (only a 5-character hash prefix leaves the server). The bundled list of 152 common passwords only catches the obvious ones.
- WebAuthn / passkeys as a phishing-resistant second factor, or as a replacement for passwords.
- Rate-limit "forgot password" per address, and send e-mails from a background worker so request timing can't distinguish known and unknown addresses.
- Move from SQLite to PostgreSQL (`SELECT … FOR UPDATE` instead of `BEGIN IMMEDIATE`) for multi-server deployments, with Redis for the per-IP counters.
- Argon2id as an alternative hash (needs the `argon2-cffi` package).

## What this project teaches

- Password storage: why slow, memory-hard, salted hashes; parameter upgrades; Unicode normalisation.
- Authentication protocols from their RFCs: scrypt, HOTP and TOTP, checked against the official test vectors.
- Web session security: cookie attributes, session fixation, CSRF, the Origin header, cache and referrer headers.
- Concurrency bugs in security code (time-of-check to time-of-use), and how database transactions fix them.
- Avoiding information leaks through error messages and timing.
- Testing security properties with attack simulations, race tests, timing measurements and planted bugs.

## License

MIT — see [LICENSE](LICENSE).
