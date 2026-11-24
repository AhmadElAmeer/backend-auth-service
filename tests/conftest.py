import os

import pytest

from authsvc import passwords
from authsvc.service import AuthService, Config
from authsvc.store import Store
from authsvc.web import create_app

# Cheap scrypt parameters keep the suite fast; tests that are about the real
# cost (timing, rehash on upgrade) set their own.
FAST = passwords.ScryptParams(ln=10, r=8, p=1)
GOOD_PASSWORD = "plum tractor violet 1987"
ORIGIN = "https://auth.example"


class Clock:
    """A controllable clock: tests move time instead of sleeping."""

    def __init__(self, t: float = 1_700_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def config():
    return Config(hash_params=FAST, data_key=os.urandom(32), issuer="authsvc")


@pytest.fixture
def service(tmp_path, config, clock):
    return AuthService(Store(tmp_path / "auth.db"), config, clock)


@pytest.fixture
def app(service):
    return create_app(service, allowed_origins={ORIGIN})


@pytest.fixture
def client(app):
    # https base URL: the session cookie is Secure and must be sent back.
    return app.test_client()


@pytest.fixture
def user(service):
    service.register("ahmad", "ahmad@example.com", GOOD_PASSWORD)
    return {"username": "ahmad", "email": "ahmad@example.com", "password": GOOD_PASSWORD}
