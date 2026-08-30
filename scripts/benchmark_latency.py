"""
Reproduces Table 3 (Performance Overhead) with real, measured numbers.

Run this ONCE PER SECURITY_LEVEL, against a server you started with that
same SECURITY_LEVEL, e.g.:

    # terminal 1
    SECURITY_LEVEL=baseline python manage.py runserver 8001

    # terminal 2
    python scripts/benchmark_latency.py --level baseline --n 200

Repeat for headers / sanitization / full, then paste the four printed
rows into the paper's Table 3, along with the environment block that
prints at the top (Python/Django version, OS, trial count).

This measures GET /ping/, a trivial view, so the number reflects the cost
of the active middleware/header stack for that SECURITY_LEVEL -- the same
thing Table 3 claims to measure -- not application logic.
"""
import argparse
import platform
import statistics
import sys
import time

import requests

try:
    import django

    DJANGO_VERSION = django.get_version()
except ImportError:
    DJANGO_VERSION = "unknown (run inside the project virtualenv)"


def run(level: str, base_url: str, n: int, warmup: int):
    url = base_url.rstrip("/") + "/ping/"

    for _ in range(warmup):
        try:
            requests.get(url, timeout=5)
        except requests.RequestException as exc:
            print(f"ERROR: could not reach {url} -- is the server running with "
                  f"SECURITY_LEVEL={level}? ({exc})", file=sys.stderr)
            sys.exit(1)

    samples_ms = []
    for _ in range(n):
        t0 = time.perf_counter()
        requests.get(url, timeout=5)
        t1 = time.perf_counter()
        samples_ms.append((t1 - t0) * 1000.0)

    mean = statistics.mean(samples_ms)
    stdev = statistics.stdev(samples_ms) if len(samples_ms) > 1 else 0.0
    median = statistics.median(samples_ms)

    print("=" * 70)
    print("Environment (record this alongside the table in the paper):")
    print(f"  Python:        {platform.python_version()}")
    print(f"  Django:        {DJANGO_VERSION}")
    print(f"  OS:            {platform.platform()}")
    print(f"  CPU:           {platform.processor() or 'see machine spec sheet'}")
    print(f"  Trials (n):    {n}  (+{warmup} warmup requests, discarded)")
    print("=" * 70)
    print(f"SECURITY_LEVEL={level}")
    print(f"  mean latency:   {mean:.2f} ms")
    print(f"  median latency: {median:.2f} ms")
    print(f"  stdev:          {stdev:.2f} ms")
    print()
    print("Paste into Table 3 as:")
    print(f"  | {level} | {mean:.1f} ms (\u00b1{stdev:.1f}) | n={n} |")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--level", required=True,
                         choices=["baseline", "headers", "sanitization", "full"],
                         help="Which SECURITY_LEVEL the target server is running (for the printed label only)")
    parser.add_argument("--url", default="http://127.0.0.1:8001",
                         help="Base URL of the running Django dev server")
    parser.add_argument("--n", type=int, default=200, help="Number of timed requests")
    parser.add_argument("--warmup", type=int, default=10, help="Untimed warmup requests")
    args = parser.parse_args()
    run(args.level, args.url, args.n, args.warmup)
