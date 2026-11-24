"""Walk through the API end to end (register, log in, enable 2FA, log in with a
code, reset a password) and print each request and response. Uses Flask's test
client and a temporary database, so nothing needs to be running.

    python scripts/demo.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from authsvc import passwords, totp                 # noqa: E402
from authsvc.service import AuthService, Config     # noqa: E402
from authsvc.store import Store                     # noqa: E402
from authsvc.web import create_app                  # noqa: E402

BASE = "https://localhost"


def show(client, method, path, body=None, headers=None, hide=()):
    r = client.open(path, method=method, json=body, headers=headers or {}, base_url=BASE)
    shown = dict(body or {})
    for k in hide:
        if k in shown:
            shown[k] = "…"
    print(f"\n{method} {path} {json.dumps(shown, ensure_ascii=False) if body else ''}".rstrip())
    data = r.get_json()
    for k in ("csrf_token", "mfa_token", "secret", "otpauth_uri"):
        if data and k in data:
            data[k] = data[k][:12] + "…"
    if data and "recovery_codes" in data:
        data["recovery_codes"] = data["recovery_codes"][:2] + ["…"]
    extra = f"  Retry-After: {r.headers['Retry-After']}" if "Retry-After" in r.headers else ""
    print(f"  → {r.status_code}{extra} {json.dumps(data, ensure_ascii=False)}")
    return r


def main():
    with tempfile.TemporaryDirectory() as d:
        svc = AuthService(Store(Path(d) / "demo.db"),
                          Config(hash_params=passwords.ScryptParams(ln=14), data_key=os.urandom(32)))
        c = create_app(svc).test_client()

        show(c, "POST", "/register", {"username": "ahmad", "email": "ahmad@example.com", "password": "Password2024!"})
        show(c, "POST", "/register", {"username": "ahmad", "email": "ahmad@example.com", "password": "plum tractor violet 1987"})
        show(c, "POST", "/login", {"username": "ahmad", "password": "wrong guess"})
        show(c, "POST", "/login", {"username": "nobody", "password": "wrong guess"})
        csrf = show(c, "POST", "/login", {"username": "ahmad", "password": "plum tractor violet 1987"}).json["csrf_token"]
        show(c, "GET", "/me")
        print("\n(without the X-CSRF-Token header:)", end="")
        show(c, "POST", "/mfa/setup")
        setup = c.post("/mfa/setup", headers={"X-CSRF-Token": csrf}, base_url=BASE).json
        key = totp.from_base32(setup["secret"])
        show(c, "POST", "/mfa/confirm", {"code": totp.totp(key, svc.clock())}, {"X-CSRF-Token": csrf})

        fresh = create_app(svc).test_client()
        mfa = show(fresh, "POST", "/login", {"username": "ahmad", "password": "plum tractor violet 1987"}).json["mfa_token"]
        show(fresh, "POST", "/login/mfa", {"mfa_token": mfa, "code": "000000"}, hide=("mfa_token",))
        # The enrolment code's time step is used; a code from the next step is needed.
        svc.clock = lambda: __import__("time").time() + 30
        show(fresh, "POST", "/login/mfa", {"mfa_token": mfa, "code": totp.totp(key, svc.clock())}, hide=("mfa_token",))

        show(c, "POST", "/password/forgot", {"email": "ahmad@example.com"})
        show(c, "POST", "/password/forgot", {"email": "someone@else.example"})
        with svc.store.read() as conn:
            body = conn.execute("SELECT body FROM outbox").fetchone()[0]
        token = re.search(r"token=(\S+)", body)[1]
        show(c, "POST", "/password/reset", {"token": token, "new_password": "marble lantern quietly 2031"}, hide=("token",))
        show(c, "GET", "/me")
        show(c, "POST", "/password/reset", {"token": token, "new_password": "another good passphrase 9"}, hide=("token",))
        for _ in range(5):
            r = c.post("/login", json={"username": "ahmad", "password": "wrong again"}, base_url=BASE)
        print("\n(five wrong passwords later)")
        show(c, "POST", "/login", {"username": "ahmad", "password": "marble lantern quietly 2031"})


if __name__ == "__main__":
    main()
