import pytest

from authsvc.service import InvalidCredentials, TooManyAttempts, sha256
from conftest import GOOD_PASSWORD

NEW_PASSWORD = "marble lantern quietly 2031"


def login(service, ip=None):
    return service.login("ahmad", GOOD_PASSWORD, ip).session


def test_idle_timeout(service, user, clock):
    s = login(service)
    clock.advance(29 * 60)
    assert service.authenticate(s.token)           # used: idle timer restarts
    clock.advance(29 * 60)
    assert service.authenticate(s.token)
    clock.advance(30 * 60 + 1)
    assert service.authenticate(s.token) is None
    assert service.authenticate(s.token) is None    # and it's gone from the database


def test_absolute_timeout_even_when_active(service, user, clock):
    s = login(service)
    for _ in range(12 * 4):                          # active every 15 minutes...
        clock.advance(15 * 60)
        assert service.authenticate(s.token)         # ...valid up to and including 12:00:00
    clock.advance(1)
    assert service.authenticate(s.token) is None     # 12 hours and 1 second: over


def test_last_seen_is_written_at_most_once_a_minute(service, user, clock):
    s = login(service)
    created = service.authenticate(s.token)["last_seen"]
    clock.advance(30)
    assert service.authenticate(s.token)["last_seen"] == created
    clock.advance(31)
    assert service.authenticate(s.token)["last_seen"] == created          # returns the row as read...
    assert service.authenticate(s.token)["last_seen"] == created + 61     # ...then it was updated


def test_tokens_are_stored_only_as_hashes(service, user):
    s = login(service)
    dump = "\n".join(service.store.connect().iterdump())
    assert s.token not in dump and s.csrf_token not in dump
    assert sha256(s.token) in dump


def test_every_login_issues_a_new_token(service, user):
    # Session fixation: a token known before login must never become authenticated.
    a, b = login(service), login(service)
    assert a.token != b.token and a.csrf_token != b.csrf_token
    assert service.authenticate(a.token) and service.authenticate(b.token)


def test_unknown_and_garbage_tokens(service, user):
    for t in [None, "", "x", "' OR 1=1 --", "a" * 5000]:
        assert service.authenticate(t) is None


def test_logout_and_logout_everywhere(service, user):
    a, b, c = login(service), login(service), login(service)
    service.logout(a.token)
    assert service.authenticate(a.token) is None and service.authenticate(b.token)
    assert service.logout_everywhere(a.user_id) == 2
    assert service.authenticate(b.token) is None and service.authenticate(c.token) is None


def test_list_and_revoke_only_your_own_sessions(service, user):
    service.register("mallory", "m@example.com", "copper kettle sings 88")
    mine = login(service, "10.0.0.1")
    theirs = service.login("mallory", "copper kettle sings 88").session
    listed = service.list_sessions(mine.user_id)
    assert [s["public_id"] for s in listed] == [mine.public_id]
    assert "token_hash" not in listed[0] and "csrf_hash" not in listed[0]
    assert not service.revoke_session(mine.user_id, theirs.public_id)   # can't revoke Mallory's
    assert service.authenticate(theirs.token)
    assert service.revoke_session(theirs.user_id, theirs.public_id)
    assert service.authenticate(theirs.token) is None


def test_password_change_replaces_every_session(service, user):
    a, b = login(service), login(service)
    new = service.change_password(a.user_id, GOOD_PASSWORD, NEW_PASSWORD)
    assert service.authenticate(a.token) is None and service.authenticate(b.token) is None
    assert service.authenticate(new.token)
    assert service.login("ahmad", NEW_PASSWORD).session


def test_password_change_with_wrong_current_password_counts_as_a_failure(service, user, clock):
    s = login(service)
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            service.change_password(s.user_id, "not my password at all", NEW_PASSWORD)
    with pytest.raises(TooManyAttempts):
        service.change_password(s.user_id, GOOD_PASSWORD, NEW_PASSWORD)
    assert service.authenticate(s.token), "a failed change doesn't end the session"
