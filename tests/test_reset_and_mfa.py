import re
import threading

import pytest

from authsvc import totp
from authsvc.service import AuthError, InvalidCredentials, InvalidToken, PolicyError, TooManyAttempts
from conftest import GOOD_PASSWORD

NEW = "marble lantern quietly 2031"


def outbox_token(service):
    with service.store.read() as conn:
        body = conn.execute("SELECT body FROM outbox ORDER BY id DESC LIMIT 1").fetchone()[0]
    return re.search(r"token=([A-Za-z0-9_-]+)", body)[1]


# ---------------------------------------------------------------- password reset

def test_reset_flow(service, user):
    s = service.login("ahmad", GOOD_PASSWORD).session
    service.request_reset("AHMAD@example.com ")
    token = outbox_token(service)
    service.reset_password(token, NEW)
    assert service.authenticate(s.token) is None, "existing sessions end"
    assert service.login("ahmad", NEW).session
    with pytest.raises(InvalidCredentials):
        service.login("ahmad", GOOD_PASSWORD)


def test_unknown_address_sends_nothing_but_is_audited(service, user):
    service.request_reset("nobody@example.com")
    with service.store.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 0
        assert conn.execute("SELECT event FROM audit ORDER BY id DESC").fetchone()[0] == "reset_requested_unknown"


def test_reset_token_is_single_use_and_stored_hashed(service, user):
    service.request_reset("ahmad@example.com")
    token = outbox_token(service)
    assert token not in "\n".join(service.store.connect().iterdump()).replace(f"token={token}", "")
    service.reset_password(token, NEW)
    with pytest.raises(InvalidToken):
        service.reset_password(token, "another fine password 7")


def test_reset_token_expires_after_30_minutes(service, user, clock):
    service.request_reset("ahmad@example.com")
    token = outbox_token(service)
    clock.advance(30 * 60 + 1)
    with pytest.raises(InvalidToken):
        service.reset_password(token, NEW)


def test_weak_new_password_doesnt_burn_the_token(service, user):
    service.request_reset("ahmad@example.com")
    token = outbox_token(service)
    with pytest.raises(PolicyError):
        service.reset_password(token, "password1")
    service.reset_password(token, NEW)


def test_changing_the_password_invalidates_outstanding_reset_links(service, user):
    service.request_reset("ahmad@example.com")
    token = outbox_token(service)
    s = service.login("ahmad", GOOD_PASSWORD).session
    service.change_password(s.user_id, GOOD_PASSWORD, NEW)
    with pytest.raises(InvalidToken):
        service.reset_password(token, "another fine password 7")


def test_reset_clears_a_lockout(service, user):
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            service.login("ahmad", "wrong wrong wrong")
    with pytest.raises(TooManyAttempts):
        service.login("ahmad", GOOD_PASSWORD)
    service.request_reset("ahmad@example.com")
    service.reset_password(outbox_token(service), NEW)
    assert service.login("ahmad", NEW).session


@pytest.mark.slow
def test_racing_two_resets_with_one_token(service, user):
    """Both requests pass the first check; only one may claim the token."""
    service.request_reset("ahmad@example.com")
    token = outbox_token(service)
    results = []
    barrier = threading.Barrier(8)

    def go(i):
        barrier.wait()
        try:
            service.reset_password(token, f"racing password number {i}")
            results.append(i)
        except InvalidToken:
            results.append(None)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    winners = [r for r in results if r is not None]
    assert len(winners) == 1
    assert service.login("ahmad", f"racing password number {winners[0]}").session


# ---------------------------------------------------------------- two-factor authentication

def enable_mfa(service, clock):
    s = service.login("ahmad", GOOD_PASSWORD).session
    setup = service.mfa_begin(s.user_id)
    key = totp.from_base32(setup["secret"])
    codes = service.mfa_confirm(s.user_id, totp.totp(key, clock()))
    clock.advance(30)   # the enrolment code's step is now used up
    return key, codes, s


def test_mfa_login_flow(service, user, clock):
    key, codes, _ = enable_mfa(service, clock)
    assert len(codes) == 10 and all(re.fullmatch(r"[A-Z2-9]{5}-[A-Z2-9]{5}", c) for c in codes)
    first = service.login("ahmad", GOOD_PASSWORD)
    assert first.session is None and first.mfa_token
    session = service.login_mfa(first.mfa_token, totp.totp(key, clock()))
    assert service.authenticate(session.token)
    with pytest.raises(InvalidToken):             # the challenge is used up
        service.login_mfa(first.mfa_token, totp.totp(key, clock()))


def test_a_totp_code_cannot_be_replayed(service, user, clock):
    key, _, _ = enable_mfa(service, clock)
    code = totp.totp(key, clock())
    service.login_mfa(service.login("ahmad", GOOD_PASSWORD).mfa_token, code)
    # Same code, a few seconds later, still inside its 30 s window: refused.
    clock.advance(5)
    with pytest.raises(InvalidCredentials):
        service.login_mfa(service.login("ahmad", GOOD_PASSWORD).mfa_token, code)
    # An older code from the drift window is refused too: steps only move forward.
    with pytest.raises(InvalidCredentials):
        service.login_mfa(service.login("ahmad", GOOD_PASSWORD).mfa_token, totp.totp(key, clock() - 30))
    clock.advance(30)
    service.login_mfa(service.login("ahmad", GOOD_PASSWORD).mfa_token, totp.totp(key, clock()))


def test_recovery_codes_work_once(service, user, clock):
    _, codes, _ = enable_mfa(service, clock)
    service.login_mfa(service.login("ahmad", GOOD_PASSWORD).mfa_token, codes[3].lower().replace("-", " "))
    with pytest.raises(InvalidCredentials):
        service.login_mfa(service.login("ahmad", GOOD_PASSWORD).mfa_token, codes[3])
    service.login_mfa(service.login("ahmad", GOOD_PASSWORD).mfa_token, codes[4])


def test_mfa_challenge_allows_five_attempts_and_expires(service, user, clock):
    key, _, _ = enable_mfa(service, clock)
    token = service.login("ahmad", GOOD_PASSWORD).mfa_token
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            service.login_mfa(token, "000000")
    with pytest.raises(InvalidToken):             # sixth try: even the right code is refused
        service.login_mfa(token, totp.totp(key, clock()))
    token = service.login("ahmad", GOOD_PASSWORD).mfa_token
    clock.advance(5 * 60 + 1)
    with pytest.raises(InvalidToken):
        service.login_mfa(token, totp.totp(key, clock()))


def test_password_reset_does_not_bypass_mfa(service, user, clock):
    key, _, _ = enable_mfa(service, clock)
    service.request_reset("ahmad@example.com")
    service.reset_password(outbox_token(service), NEW)
    assert service.login("ahmad", NEW).mfa_token, "a second factor is still required"


def test_totp_secret_is_encrypted_and_bound_to_the_user(service, user, clock):
    key, _, s = enable_mfa(service, clock)
    with service.store.read() as conn:
        blob = conn.execute("SELECT totp_secret FROM users WHERE id = ?", (s.user_id,)).fetchone()[0]
    assert key not in blob and totp.to_base32(key).encode() not in blob
    assert service._decrypt(s.user_id, blob) == key
    with pytest.raises(Exception):                # moved to another user's row, it won't decrypt
        service._decrypt(s.user_id + 1, blob)


def test_enrolment_needs_a_valid_code_and_disable_needs_the_password(service, user, clock):
    s = service.login("ahmad", GOOD_PASSWORD).session
    with pytest.raises(AuthError):
        service.mfa_confirm(s.user_id, "123456")      # not started
    setup = service.mfa_begin(s.user_id)
    with pytest.raises(InvalidCredentials):
        service.mfa_confirm(s.user_id, "000000")
    service.mfa_confirm(s.user_id, totp.totp(totp.from_base32(setup["secret"]), clock()))
    with pytest.raises(AuthError):
        service.mfa_begin(s.user_id)                  # already on
    with pytest.raises(InvalidCredentials):
        service.mfa_disable(s.user_id, "not the password!!")
    service.mfa_disable(s.user_id, GOOD_PASSWORD)
    assert service.login("ahmad", GOOD_PASSWORD).session


def test_mfa_over_http(client, user, clock):
    base = "https://localhost"
    csrf = client.post("/login", json={"username": "ahmad", "password": GOOD_PASSWORD}, base_url=base).json["csrf_token"]
    h = {"X-CSRF-Token": csrf}
    setup = client.post("/mfa/setup", headers=h, base_url=base).json
    key = totp.from_base32(setup["secret"])
    r = client.post("/mfa/confirm", json={"code": totp.totp(key, clock())}, headers=h, base_url=base)
    assert len(r.json["recovery_codes"]) == 10
    clock.advance(30)
    fresh = client.application.test_client()
    first = fresh.post("/login", json={"username": "ahmad", "password": GOOD_PASSWORD}, base_url=base)
    assert first.json["mfa_required"] and "Set-Cookie" not in first.headers
    second = fresh.post("/login/mfa", json={"mfa_token": first.json["mfa_token"], "code": totp.totp(key, clock())}, base_url=base)
    assert second.status_code == 200 and "Set-Cookie" in second.headers
    assert fresh.get("/me", base_url=base).json["username"] == "ahmad"
