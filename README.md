# Reproducible test kit for "Web Security Enhancement in Django"

This is a runnable companion to the paper. It regenerates **Table 2**
(Empirical Results) and **Table 3** (Performance Overhead) with real,
scripted, re-runnable measurements — instead of the illustrative
estimates the current draft honestly (and correctly) flags as
non-reproducible.

It cannot be run inside this chat's sandbox (no internet access here to
install Django), so it's built to run on **your own machine**, where you
already have Python and can install packages.

## 1. Setup (once)

```bash
cd django_test_kit
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Record these three lines for the paper's methodology section — a
reviewer asking "which Python/Django version, which OS" should get an
exact answer:

```bash
python --version
python -c "import django; print(django.get_version())"
python -c "import platform; print(platform.platform())"
```

## 2. Run one configuration at a time

Each of the paper's four configuration rows (baseline / headers /
sanitization / full) is a **separate server run** with a different
`SECURITY_LEVEL`. Because the `full` level changes a model field type
(plain `TextField` \u2192 `EncryptedTextField`), reset the database and
migrations between different levels:

```bash
# --- reset before switching levels ---
rm -f db.sqlite3
rm -f secapp/migrations/0*.py

# --- pick ONE level, then migrate + run ---
export SECURITY_LEVEL=baseline        # or headers / sanitization / full
python manage.py makemigrations secapp
python manage.py migrate
python manage.py runserver 8001
```

Leave that server running in one terminal for the rest of this section.

## 3. Reproduce Table 3 (latency) for this level

In a second terminal, same venv:

```bash
python scripts/benchmark_latency.py --level baseline --n 200
```

This prints the environment block, mean/median/stdev latency over `n`
real HTTP requests to `/ping/`, and a ready-to-paste table row. Use the
same `--n` for all four levels so the comparison is apples-to-apples;
200–500 is reasonable for a laptop-scale benchmark. If you want a
heavier, industry-standard load tool instead of this script, `wrk` or
`locust` work too — just record the tool name, concurrency, and duration
you used, the same way this script records `n`.

## 4. Reproduce Table 2 (attack outcomes) for this level

Same terminal:

```bash
python scripts/run_attack_tests.py --level baseline \
    --url http://127.0.0.1:8001 --db "$(pwd)/db.sqlite3"
```

This actually sends the exact payloads from Table 2 (`<script>alert(document.cookie)</script>`,
a token-less forged POST, `' OR '1'='1' --`, a clickjacking header check,
and a direct raw-SQLite read of a written secret) and reports a real
Vulnerable/Secured outcome per class, saved to
`attack_results_<level>.json`. **Note on scope:** this kit exercises 5 of
the paper's 6 Table 2 rows (XSS, CSRF, SQLi, Clickjacking, Data-at-rest
exposure). Privilege escalation / access control needs a real
authenticated-session flow to test honestly — it's left out rather than
faked; if you want it, it's the natural next extension (add a login flow
and an object-ownership check, then a matching test function).

## 5. Repeat for all four levels

Stop the server (Ctrl+C), repeat steps 2–4 for `headers`, `sanitization`,
then `full`. You'll end up with four `attack_results_*.json` files and
four latency printouts — the real data for Table 2 and Table 3.

## 6. Recompute WDCS from the real results

```bash
python scripts/compute_wdcs.py \
    attack_results_baseline.json attack_results_headers.json \
    attack_results_sanitization.json attack_results_full.json
```

This replaces the paper's illustrative Ci/WDCS worked example with
scores computed from what your server actually did, for the 5 classes
this kit measures.

## 7. What to change in the paper afterward

- Table 3: replace the four latency rows with your printed mean \u00b1
  stdev, and add the environment block (Python/Django version, OS, CPU,
  `n`) either inline or as a footnote.
- Table 2: replace the qualitative Vulnerable/Secured cells with your
  real outcomes, and cite the payload + HTTP status/response you
  observed (the JSON files are your raw evidence — keep them as
  supplementary material if the venue allows it).
- The WDCS worked example: either keep it as a labeled illustrative
  example (make sure the paper says so explicitly) or replace it with
  the real per-class Ci from `compute_wdcs.py`, and say which one you
  did.
- Remove or rewrite the "Methodology disclosure" and CSRF/SQLi
  parenthetical notes that currently say the numbers are estimates —
  once you've run this kit, they're not estimates anymore, so the note
  should describe the real methodology (tool, trial count, environment)
  instead of disclaiming it.
