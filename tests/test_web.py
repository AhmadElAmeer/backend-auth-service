"""The HTTP layer: cookies, CSRF, Origin checks, headers, input handling."""

import json
import random

import pytest

from authsvc.web import COOKIE
from conftest import GOOD_PASSWORD, ORIGIN

HTTPS = "https://localhost"


def post(client, path, data=None, **kw):
    return client.post(path, json=data, base_url=HTTPS, **kw)


def login(client, username="ahmad", password=GOOD_PASSWORD):
    r = post(client, "/login", {"username": username, "password": password})
    assert r.status_code == 200, r.json
    return r


def test_register_login_me_logout(client):
    r = post(client, "/register", {"username": "Ahmad", "email": "ahmad@example.com", "password": GOOD_PASSWORD})
    assert r.status_code == 201
    csrf = login(client).json["csrf_token"]
    me = client.get("/me", base_url=HTTPS).json
    assert me["username"] == "Ahmad" and me["email"] == "ahmad@example.com"
    assert post(client, "/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert client.get("/me", base_url=HTTPS).status_code == 401


def test_session_cookie_flags(client, user):
    cookie = login(client).headers["Set-Cookie"]
    name, _, attrs = cookie.partition("; ")
    assert name.startswith(COOKIE + "=") and COOKIE.startswith("__Host-")
    for flag in ["Secure", "HttpOnly", "Path=/", "SameSite=Lax"]:
        assert flag in attrs
    assert "Domain" not in attrs


def test_csrf_token_required_for_changes_not_for_reads(client, user):
    csrf = login(client).json["csrf_token"]
    assert client.get("/sessions", base_url=HTTPS).status_code == 200
    for headers in [{}, {"X-CSRF-Token": "wrong"}, {"X-CSRF-Token": csrf[:-1]}]:
        r = post(client, "/logout-all", headers=headers)
        assert r.status_code == 403 and r.json["error"] == "csrf"
    assert post(client, "/logout-all", headers={"X-CSRF-Token": csrf}).status_code == 200


def test_csrf_token_of_another_session_is_rejected(client, app, user):
    other = app.test_client()
    their_csrf = login(other).json["csrf_token"]
    login(client)
    assert post(client, "/logout-all", headers={"X-CSRF-Token": their_csrf}).status_code == 403


def test_cross_site_origin_is_refused_even_for_login(client, user):
    data = {"username": "ahmad", "password": GOOD_PASSWORD}
    assert post(client, "/login", data, headers={"Origin": "https://evil.example"}).status_code == 403
    assert post(client, "/login", data, headers={"Origin": ORIGIN}).status_code == 200
    assert post(client, "/login", data).status_code == 200       # non-browser clients send no Origin


def test_errors_carry_retry_after_and_never_leak_details(client, user):
    for _ in range(5):
        r = post(client, "/login", {"username": "ahmad", "password": "nope nope nope"})
    r = post(client, "/login", {"username": "ahmad", "password": GOOD_PASSWORD})
    assert r.status_code == 429 and r.headers["Retry-After"] == "1"
    a = post(client, "/login", {"username": "ghost", "password": "nope nope nope"})
    b = post(client, "/login", {"username": "ahmad2", "password": "nope nope nope"})
    assert a.status_code == b.status_code == 401 and a.json == b.json


def test_forgot_password_answer_is_the_same_for_any_address(client, user):
    a = post(client, "/password/forgot", {"email": "ahmad@example.com"})
    b = post(client, "/password/forgot", {"email": "nobody@example.com"})
    assert a.status_code == b.status_code == 202 and a.json == b.json


def test_security_headers(client, user):
    r = login(client)
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_weak_password_is_explained(client):
    r = post(client, "/register", {"username": "ahmad", "email": "a@example.com", "password": "password123!"})
    assert r.status_code == 400 and r.json["error"] == "weak_password"
    assert any("commonly used" in p for p in r.json["problems"])


def test_duplicate_registration(client, user):
    r = post(client, "/register", {"username": "AHMAD", "email": "x@example.com", "password": GOOD_PASSWORD})
    assert r.status_code == 409


def test_big_bodies_are_refused(client):
    r = client.post("/login", data="x" * 20000, content_type="application/json", base_url=HTTPS)
    assert r.status_code == 413


def test_fuzzed_requests_never_cause_a_server_error(client, user):
    """500 random bodies against every endpoint: only 4xx or 2xx, always JSON."""
    rng = random.Random(15)
    values = [None, 0, -1, 1.5, True, "", " ", "ahmad", GOOD_PASSWORD, "' OR '1'='1", "\u0000", "𝔘𝔫𝔦𝔠𝔬𝔡𝔢",
              "１２３４５６", "a" * 2000, [], {}, ["ahmad"], {"$ne": None}]
    keys = ["username", "password", "email", "token", "new_password", "current_password", "mfa_token", "code", "x"]
    paths = ["/register", "/login", "/login/mfa", "/password/forgot", "/password/reset"]
    login(client)
    for i in range(500):
        body = {rng.choice(keys): rng.choice(values) for _ in range(rng.randrange(0, 5))}
        raw = json.dumps(body) if rng.random() < 0.9 else rng.choice(["{", "[]", "null", "\"x\"", "{\"a\":}"])
        r = client.post(rng.choice(paths), data=raw, content_type="application/json", base_url=HTTPS)
        assert r.status_code < 500, (i, raw, r.data[:200])
        assert r.is_json, (i, raw)


def test_sql_injection_strings_are_just_data(client, service):
    # Quotes are legal in e-mail addresses; every query is parameterised.
    r = post(client, "/register", {"username": "obrien", "email": "o'brien@example.com", "password": GOOD_PASSWORD})
    assert r.status_code == 201
    for attack in ["' OR '1'='1", "obrien'--", "x'; DROP TABLE users; --"]:
        assert post(client, "/login", {"username": attack, "password": "' OR '1'='1"}).status_code in (400, 401)
        assert post(client, "/password/forgot", {"email": attack}).status_code == 202
    post(client, "/password/forgot", {"email": "O'Brien@example.com"})
    with service.store.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert conn.execute("SELECT to_addr FROM outbox").fetchall()[0][0] == "o'brien@example.com"
    assert login(client, "obrien").status_code == 200
