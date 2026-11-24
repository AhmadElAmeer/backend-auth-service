"""JSON API over the auth service.

Cookie: `__Host-session`, HttpOnly, Secure, SameSite=Lax, Path=/. The __Host-
prefix makes browsers refuse the cookie unless it is Secure, has no Domain and
Path=/, so a sibling subdomain can't plant or overwrite it.

CSRF: every state-changing request made with a session must carry the
session's CSRF token in an `X-CSRF-Token` header (returned at login). A
cross-site form can send the cookie but can't read or set that header. As a
second layer, a request whose Origin header names another site is refused.
"""

from __future__ import annotations

import os
from functools import wraps

from flask import Flask, g, jsonify, request

from .service import AuthError, AuthService, Config, NotAuthenticated, Session
from .store import Store

COOKIE = "__Host-session"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def create_app(service: AuthService | None = None, *, allowed_origins: set[str] | None = None,
               trust_proxy: bool = False) -> Flask:
    app = Flask(__name__)
    if service is None:
        key = bytes.fromhex(os.environ["AUTH_DATA_KEY"]) if "AUTH_DATA_KEY" in os.environ else b""
        service = AuthService(Store(os.environ.get("AUTH_DB", "auth.db")), Config(data_key=key))
    app.config["SERVICE"] = service
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    origins = allowed_origins if allowed_origins is not None else {"https://localhost"}

    def client_ip() -> str:
        if trust_proxy and request.headers.get("X-Forwarded-For"):
            # Only behind a proxy you control, which sets this header itself.
            return request.headers["X-Forwarded-For"].split(",")[-1].strip()
        return request.remote_addr or "unknown"

    def body() -> dict:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise AuthError("Send a JSON object.")
        return data

    def field(data: dict, name: str, max_len: int = 1024) -> str:
        value = data.get(name)
        if not isinstance(value, str) or not value or len(value) > max_len:
            raise AuthError(f"'{name}' is required.")
        return value

    def set_cookie(resp, session: Session):
        resp.set_cookie(COOKIE, session.token, httponly=True, secure=True, samesite="Lax", path="/",
                        max_age=int(service.config.session_absolute))
        return resp

    def session_response(session: Session, status: int = 200):
        return set_cookie(jsonify(csrf_token=session.csrf_token, session=session.public_id), session), status

    @app.before_request
    def check_origin():
        origin = request.headers.get("Origin")
        if request.method in UNSAFE and origin is not None and origin not in origins:
            return jsonify(error="forbidden_origin", message="Cross-site request refused."), 403
        return None

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            s = service.authenticate(request.cookies.get(COOKIE))
            if s is None:
                raise NotAuthenticated("Sign in first.")
            if request.method in UNSAFE and not service.check_csrf(s, request.headers.get("X-CSRF-Token")):
                return jsonify(error="csrf", message="Missing or wrong CSRF token."), 403
            g.session = s
            return fn(*args, **kwargs)
        return wrapper

    @app.errorhandler(AuthError)
    def on_auth_error(e: AuthError):
        resp = jsonify(error=e.code, message=e.message, **{k: v for k, v in e.extra.items()})
        if "retry_after" in e.extra:
            resp.headers["Retry-After"] = str(e.extra["retry_after"])
        return resp, e.status

    @app.after_request
    def security_headers(resp):
        resp.headers["Cache-Control"] = "no-store"     # responses carry tokens and personal data
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"  # reset links must not leak via Referer
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return resp

    # ---------------------------------------------------------------- routes

    @app.post("/register")
    def register():
        d = body()
        user_id = service.register(field(d, "username", 64), field(d, "email", 254), field(d, "password", 1024), client_ip())
        return jsonify(id=user_id), 201

    @app.post("/login")
    def login():
        d = body()
        result = service.login(field(d, "username", 64), field(d, "password", 1024), client_ip(),
                               request.headers.get("User-Agent", ""))
        if result.mfa_token:
            return jsonify(mfa_required=True, mfa_token=result.mfa_token), 200
        return session_response(result.session)

    @app.post("/login/mfa")
    def login_mfa():
        d = body()
        return session_response(service.login_mfa(field(d, "mfa_token", 100), field(d, "code", 20), client_ip()))

    @app.post("/logout")
    @login_required
    def logout():
        service.logout(request.cookies[COOKIE])
        resp = jsonify(ok=True)
        resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
        return resp

    @app.post("/logout-all")
    @login_required
    def logout_all():
        n = service.logout_everywhere(g.session["user_id"])
        resp = jsonify(ok=True, sessions_ended=n)
        resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
        return resp

    @app.get("/me")
    @login_required
    def me():
        s = g.session
        return jsonify(id=s["user_id"], username=s["display_name"], email=s["email"], session=s["public_id"])

    @app.get("/sessions")
    @login_required
    def sessions():
        rows = service.list_sessions(g.session["user_id"])
        for r in rows:
            r["current"] = r["public_id"] == g.session["public_id"]
        return jsonify(sessions=rows)

    @app.delete("/sessions/<public_id>")
    @login_required
    def revoke(public_id):
        if not service.revoke_session(g.session["user_id"], public_id):
            return jsonify(error="not_found", message="No such session."), 404
        return jsonify(ok=True)

    @app.post("/password/change")
    @login_required
    def change_password():
        d = body()
        session = service.change_password(g.session["user_id"], field(d, "current_password"), field(d, "new_password"),
                                          client_ip(), request.headers.get("User-Agent", ""))
        return session_response(session)

    @app.post("/password/forgot")
    def forgot():
        service.request_reset(field(body(), "email", 254), client_ip())
        # Same answer whether or not the address is registered.
        return jsonify(message="If that address has an account, we've sent a reset link."), 202

    @app.post("/password/reset")
    def reset():
        d = body()
        service.reset_password(field(d, "token", 100), field(d, "new_password"), client_ip())
        return jsonify(ok=True, message="Password changed. Sign in with the new password.")

    @app.post("/mfa/setup")
    @login_required
    def mfa_setup():
        return jsonify(service.mfa_begin(g.session["user_id"]))

    @app.post("/mfa/confirm")
    @login_required
    def mfa_confirm():
        codes = service.mfa_confirm(g.session["user_id"], field(body(), "code", 20))
        return jsonify(recovery_codes=codes, message="Save these codes somewhere safe; each works once.")

    @app.post("/mfa/disable")
    @login_required
    def mfa_disable():
        service.mfa_disable(g.session["user_id"], field(body(), "password"), client_ip())
        return jsonify(ok=True)

    return app


if __name__ == "__main__":   # development only: python -m authsvc.web
    create_app().run(port=5000, ssl_context="adhoc" if os.environ.get("AUTH_HTTPS") else None)
