"""How many passwords can an online attacker try?

Simulates attackers against the real AuthService with a simulated clock (so a
day of attacking runs in seconds) and counts the guesses that were actually
checked. Hashing uses cheap parameters here; the *number* of guesses depends
only on the throttling policy.

    python scripts/attack_sim.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from authsvc import passwords                                   # noqa: E402
from authsvc.service import AuthService, Config, InvalidCredentials, TooManyAttempts  # noqa: E402
from authsvc.store import Store                                 # noqa: E402

FAST = passwords.ScryptParams(ln=4, r=1)
PASSWORD = "plum tractor violet 1987"


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def attack_one_account(config: Config, hours: float, ip_rotation: bool) -> tuple[int, float]:
    """An attacker guessing one account's password as fast as the service allows.
    Returns (guesses checked, longest lock seen in seconds)."""
    clock = Clock()
    with tempfile.TemporaryDirectory() as d:
        svc = AuthService(Store(Path(d) / "sim.db"), config, clock)
        svc.register("victim", "victim@example.com", PASSWORD)
        checked = 0
        longest = 0.0
        i = 0
        while clock.t < hours * 3600:
            i += 1
            ip = f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}" if ip_rotation else "203.0.113.7"
            try:
                svc.login("victim", f"guess {i}", ip)
                raise AssertionError("the attacker guessed the password")
            except InvalidCredentials:
                checked += 1
                clock.t += 0.05            # a fast attacker: 20 requests a second
            except TooManyAttempts as e:
                longest = max(longest, e.extra["retry_after"])
                clock.t += e.extra["retry_after"]   # wait exactly as long as told
        return checked, longest


def spray_from_one_ip(config: Config, hours: float) -> int:
    """Password spraying: one common password against many usernames from one IP."""
    clock = Clock()
    with tempfile.TemporaryDirectory() as d:
        svc = AuthService(Store(Path(d) / "sim.db"), config, clock)
        checked = 0
        i = 0
        while clock.t < hours * 3600:
            i += 1
            try:
                svc.login(f"user{i}", "Summer2026!", "203.0.113.7")
            except InvalidCredentials:
                checked += 1
                clock.t += 0.05
            except TooManyAttempts as e:
                clock.t += e.extra["retry_after"]
        return checked


def main():
    policy = Config(hash_params=FAST)
    print("Guesses checked against one account (attacker sends 20 requests/s and waits when told to):\n")
    print("| policy | 1 hour | 24 hours | longest lock |")
    print("|---|---:|---:|---:|")
    # Without throttling every request is checked, so the count is just the request rate.
    print(f"| no throttling (20 requests/s) | {20 * 3600:,} | {20 * 86400:,} | – |")
    for label, cfg, rotate in [("this service, one IP", policy, False),
                               ("this service, new IP every request", policy, True)]:
        h1, _ = attack_one_account(cfg, 1, rotate)
        h24, longest = attack_one_account(cfg, 24, rotate)
        print(f"| {label} | {h1:,} | {h24:,} | {longest:,.0f} s |")
    print()
    print(f"Password spraying from one IP (one guess per username): {spray_from_one_ip(policy, 1):,} guesses in 1 hour, "
          f"{spray_from_one_ip(policy, 24):,} in 24 hours")


if __name__ == "__main__":
    main()
