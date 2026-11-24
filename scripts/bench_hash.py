"""What does one password hash cost, at several scrypt settings?

Each setting runs in a fresh process so peak memory (ru_maxrss) belongs to
that setting alone. Also times a full failed login through the HTTP API at
the default setting.

    python scripts/bench_hash.py
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CHILD = r"""
import json, resource, statistics, sys, time
sys.path.insert(0, sys.argv[1])
from authsvc.passwords import ScryptParams, hash_password, verify_password
ln = int(sys.argv[2])
p = ScryptParams(ln=ln)
base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
h = hash_password("plum tractor violet 1987", p)
times = []
for _ in range(int(sys.argv[3])):
    t = time.perf_counter(); verify_password("plum tractor violet 1987", h); times.append(time.perf_counter() - t)
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({"ln": ln, "median_ms": statistics.median(times) * 1000, "min_ms": min(times) * 1000,
                  "rss_growth_mib": (peak - base) / 1024}))
"""


def main():
    print(f"{platform.processor() or platform.machine()}, {os.cpu_count()} cores, Python {platform.python_version()}\n")
    print("| scrypt setting | memory needed | verify, median | verify, fastest | process memory growth | max guesses/s per core |")
    print("|---|---:|---:|---:|---:|---:|")
    for ln in (14, 15, 16, 17):
        runs = 15 if ln < 17 else 9
        out = subprocess.run([sys.executable, "-c", CHILD, str(ROOT), str(ln), str(runs)],
                             capture_output=True, text=True, check=True).stdout
        r = json.loads(out)
        need = 128 * 8 * 2 ** ln / 2 ** 20
        print(f"| N=2^{ln}, r=8, p=1 | {need:.0f} MiB | {r['median_ms']:.0f} ms | {r['min_ms']:.0f} ms | "
              f"{r['rss_growth_mib']:.0f} MiB | {1000 / r['median_ms']:.1f} |")

    # End to end: a failed login over the API, default parameters.
    from authsvc.service import AuthService, Config
    from authsvc.store import Store
    from authsvc.web import create_app
    with tempfile.TemporaryDirectory() as d:
        svc = AuthService(Store(Path(d) / "b.db"), Config(lock_threshold=10 ** 9, ip_max_failures=10 ** 9))
        svc.register("ahmad", "a@example.com", "plum tractor violet 1987")
        client = create_app(svc).test_client()
        for label, name in [("existing user, wrong password", "ahmad"), ("unknown user", "nobody")]:
            times = []
            for _ in range(9):
                t = time.perf_counter()
                r = client.post("/login", json={"username": name, "password": "wrong guess 123"}, base_url="https://localhost")
                times.append(time.perf_counter() - t)
                assert r.status_code == 401
            print(f"\nFailed login over the API at the default setting, {label}: median {statistics.median(times) * 1000:.0f} ms")


if __name__ == "__main__":
    main()
