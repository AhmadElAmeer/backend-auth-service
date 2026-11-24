import statistics
import threading
import time

import pytest

from authsvc import passwords, service as service_module
from authsvc.service import AuthService, Config, InvalidCredentials, TooManyAttempts
from authsvc.store import Store
from conftest import FAST, GOOD_PASSWORD, Clock

WRONG = "definitely not it 42"


def failures(service, username):
    with service.store.read() as conn:
        row = conn.execute("SELECT count, locked_until FROM login_failures WHERE username_key = ?", (username,)).fetchone()
    return tuple(row) if row else None


def test_login_success_creates_a_session(service, user):
    result = service.login("ahmad", GOOD_PASSWORD, "10.0.0.1", "pytest")
    assert result.mfa_token is None
    s = service.authenticate(result.session.token)
    assert s["user_id"] == 1 and s["ip"] == "10.0.0.1" and s["user_agent"] == "pytest"


def test_username_is_case_and_width_insensitive(service, user):
    assert service.login("AHMAD", GOOD_PASSWORD).session
    assert service.login("ａｈｍａｄ", GOOD_PASSWORD).session   # full-width letters, NFKC-normalised


def test_unknown_user_and_wrong_password_look_identical(service, user):
    with pytest.raises(InvalidCredentials) as a:
        service.login("ahmad", WRONG)
    with pytest.raises(InvalidCredentials) as b:
        service.login("nobody-here", WRONG)
    assert (a.value.status, a.value.code, a.value.message, a.value.extra) == \
           (b.value.status, b.value.code, b.value.message, b.value.extra)


def test_lockout_doubles_from_1s_to_15min_and_applies_to_unknown_names_too(service, user, clock):
    for name in ["ahmad", "nobody-here"]:
        locks = []
        for attempt in range(1, 20):
            try:
                service.login(name, WRONG)
            except InvalidCredentials:
                pass
            count, locked_until = failures(service, name)
            assert count == attempt
            locks.append(round(locked_until - clock(), 3) if locked_until else 0)
            # While locked, even the right password is refused without being checked.
            if locked_until:
                with pytest.raises(TooManyAttempts) as e:
                    service.login(name, GOOD_PASSWORD)
                assert e.value.extra["retry_after"] == max(1, int(-(-(locked_until - clock()) // 1)))
                clock.advance(locked_until - clock())
        assert locks == [0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 900, 900, 900, 900, 900], name


def test_success_clears_the_counter(service, user, clock):
    for _ in range(4):
        with pytest.raises(InvalidCredentials):
            service.login("ahmad", WRONG)
    assert failures(service, "ahmad")[0] == 4
    service.login("ahmad", GOOD_PASSWORD)
    assert failures(service, "ahmad") is None
    for _ in range(4):   # a fresh allowance of 4 before any lock
        with pytest.raises(InvalidCredentials):
            service.login("ahmad", WRONG)


def test_ip_limit_across_many_usernames(tmp_path, clock):
    svc = AuthService(Store(tmp_path / "a.db"), Config(hash_params=FAST, ip_max_failures=10, ip_window=60), clock)
    for i in range(10):
        with pytest.raises(InvalidCredentials):
            svc.login(f"user{i}", WRONG, ip="203.0.113.9")
    with pytest.raises(TooManyAttempts) as e:
        svc.login("user99", WRONG, ip="203.0.113.9")
    assert e.value.extra["retry_after"] == 60
    with pytest.raises(InvalidCredentials):          # another IP is unaffected
        svc.login("user99", WRONG, ip="198.51.100.1")
    clock.advance(61)                                 # the window slides
    with pytest.raises(InvalidCredentials):
        svc.login("user99", WRONG, ip="203.0.113.9")


@pytest.mark.slow
def test_concurrent_guesses_cannot_exceed_the_threshold(service, user, monkeypatch):
    """50 simultaneous wrong guesses: exactly 5 passwords are checked, 45 are refused.
    With check-then-count, all 50 would pass the "locked?" check first."""
    checked = []
    real_verify = passwords.verify_password

    def counting_verify(pw, encoded):
        checked.append(pw)
        time.sleep(0.02)     # widen the race window
        return real_verify(pw, encoded)

    monkeypatch.setattr(service_module.passwords, "verify_password", counting_verify)
    outcomes = []
    barrier = threading.Barrier(50)

    def attack(i):
        barrier.wait()
        try:
            service.login("ahmad", f"guess number {i}")
            outcomes.append("ok")
        except InvalidCredentials:
            outcomes.append("wrong")
        except TooManyAttempts:
            outcomes.append("locked")

    threads = [threading.Thread(target=attack, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(checked) == 5
    assert sorted(outcomes).count("wrong") == 5 and outcomes.count("locked") == 45


def test_a_weaker_stored_hash_is_upgraded_at_login(tmp_path, clock):
    old = AuthService(Store(tmp_path / "a.db"), Config(hash_params=passwords.ScryptParams(ln=10)), clock)
    old.register("ahmad", "a@example.com", GOOD_PASSWORD)
    new = AuthService(Store(tmp_path / "a.db"), Config(hash_params=passwords.ScryptParams(ln=11)), clock)
    get = lambda: new.store.connect().execute("SELECT password_hash FROM users").fetchone()[0]
    assert get().startswith("$scrypt$ln=10,")
    new.login("ahmad", GOOD_PASSWORD)
    assert get().startswith("$scrypt$ln=11,")
    assert new.login("ahmad", GOOD_PASSWORD).session     # still the same password
    with new.store.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit WHERE event = 'password_rehashed'").fetchone()[0] == 1


@pytest.mark.slow
def test_timing_does_not_reveal_whether_an_account_exists(tmp_path):
    """With realistic hashing cost, a failed login for a made-up username takes
    as long as one for a real username: both run scrypt once."""
    params = passwords.ScryptParams(ln=14)     # 16 MiB, tens of milliseconds
    svc = AuthService(Store(tmp_path / "t.db"), Config(hash_params=params, lock_threshold=10 ** 6), Clock())
    svc.register("ahmad", "a@example.com", GOOD_PASSWORD)

    def timed(name):
        t = time.perf_counter()
        with pytest.raises(InvalidCredentials):
            svc.login(name, WRONG)
        return time.perf_counter() - t

    real, fake = [], []
    for i in range(15):   # interleaved, so machine noise affects both equally
        real.append(timed("ahmad"))
        fake.append(timed(f"ghost{i}"))
    r, f = statistics.median(real), statistics.median(fake)
    print(f"\nmedian failed login: existing user {r * 1000:.1f} ms, unknown user {f * 1000:.1f} ms")
    assert abs(r - f) / r < 0.25, (r, f)
    assert r > 0.01, "hashing should dominate the request"


@pytest.mark.slow
def test_at_most_n_hashes_run_at_once(tmp_path, monkeypatch):
    svc = AuthService(Store(tmp_path / "c.db"), Config(hash_params=FAST, max_concurrent_hashes=2,
                                                       lock_threshold=10 ** 6), Clock())
    running, peak = [0], [0]
    lock = threading.Lock()
    real_verify = passwords.verify_password

    def slow_verify(pw, encoded):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.05)
        with lock:
            running[0] -= 1
        return real_verify(pw, encoded)

    monkeypatch.setattr(service_module.passwords, "verify_password", slow_verify)
    threads = [threading.Thread(target=lambda i=i: pytest.raises(InvalidCredentials, svc.login, f"u{i}", WRONG))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak[0] == 2
