# django-security-wdcs

Reproducible test kit for the paper *"WDCS Revisited: A Weight-Robust, Verifiable Coverage Metric for Tracking Django Security Posture"*.

It contains a small, deliberately vulnerable Django project that can run in four hardening configurations, scripts that attack each configuration and record the outcome, a script that turns those outcomes into WDCS scores, and the sensitivity-analysis scripts used in the paper.

> The Django app in this repository is intentionally insecure at the `baseline` level. It is a local test target only. Do not deploy it.

## What reproduces which paper table

| Paper table | How to reproduce | Output |
|---|---|---|
| Table 6 (attack-test outcomes) | `scripts/run_attack_tests.py`, once per level | `attack_results_<level>.json` |
| Tables 7 and 8 (coverage and WDCS) | `scripts/compute_wdcs.py` on the four JSON files | printed table |
| Table 9 (latency, exploratory) | `scripts/benchmark_latency.py`, once per level | printed rows |
| Tables 3 and 4 (weight sensitivity, CI gates) | `scripts/wdcs_sensitivity.py`, `scripts/wdcs_tradeoff_sensitivity.py` | printed tables |
| Table 5 (synthetic trade-off scenarios) | `scripts/wdcs_tradeoff_sensitivity.py` | printed table |

## Layout

```
scripts/run_attack_tests.py          attack tests (XSS, CSRF, SQLi, clickjacking, data-at-rest)
scripts/compute_wdcs.py              WDCS from the four attack_results_*.json files
scripts/benchmark_latency.py         exploratory latency measurement (GET /ping/)
scripts/wdcs_sensitivity.py          Monte Carlo weight perturbation on the measured layers
scripts/wdcs_tradeoff_sensitivity.py synthetic trade-off scenarios and CI-gate analysis
secapp/, testproject/, manage.py     the Django test project
attack_results_*.json                raw outputs of run_attack_tests.py for the four levels
```

## 1. Setup (once)

Windows (cmd):

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

macOS / Linux:

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Record the environment used for a run:

```
python --version
python -c "import django; print(django.get_version())"
python -c "import platform; print(platform.platform())"
```

The paper's runs used Python 3.10.0, Django 5.0.14, Windows 10 build 10.0.22631 (AMD64), SQLite.

## 2. Run one configuration level

There are four levels, selected by the `SECURITY_LEVEL` environment variable: `baseline`, `headers`, `sanitization`, `full`. The `full` level changes a model field type, so reset the database and migrations before each level.

Windows (cmd), terminal 1:

```
del db.sqlite3
del secapp\migrations\0*.py
set SECURITY_LEVEL=baseline
python manage.py makemigrations secapp
python manage.py migrate
python manage.py runserver 8001
```

macOS / Linux, terminal 1:

```
rm -f db.sqlite3 secapp/migrations/0*.py
export SECURITY_LEVEL=baseline
python manage.py makemigrations secapp
python manage.py migrate
python manage.py runserver 8001
```

Leave the server running. In a second terminal (same virtual environment, same folder):

```
python scripts/run_attack_tests.py --level baseline --url http://127.0.0.1:8001 --db <absolute path to db.sqlite3>
```

On Windows use backslashes and a full path, for example `--db C:\path\to\repo\db.sqlite3`. The result is saved as `attack_results_baseline.json`. Stop the server (Ctrl+C), then repeat this section for `headers`, `sanitization`, and `full`, changing the level name in both terminals.

Optional, for Table 9 (use the same `--n` for every level):

```
python scripts/benchmark_latency.py --level baseline --n 200
```

## 3. Compute WDCS from the results

```
python scripts/compute_wdcs.py attack_results_baseline.json attack_results_headers.json attack_results_sanitization.json attack_results_full.json
```

The script refuses to score a result whose outcome is `INCONCLUSIVE` or `ERROR` instead of silently counting it as unprotected.

## 4. Sensitivity analysis (paper Section 4.4)

Python standard library only, fixed seeds.

```
python scripts/wdcs_sensitivity.py
python scripts/wdcs_tradeoff_sensitivity.py
```

`wdcs_sensitivity.py` perturbs the severity weights on the four measured layers. `wdcs_tradeoff_sensitivity.py` also analyses three **synthetic** trade-off scenarios; those are illustrations of the scoring function, not attack-test results.

## What each attack test measures

* **XSS**: whether the payload is reflected unescaped in the response body. It does not execute the script in a browser, so a Content-Security-Policy header does not change this result.
* **CSRF**: whether a POST with no CSRF token or cookie is rejected (HTTP 403).
* **SQL injection**: seed-then-inject. The test writes a known row through the app, confirms that a normal lookup finds it (positive control), then sends `' OR '1'='1' --`. If the seed or the control fails, the outcome is `INCONCLUSIVE`. An earlier version injected into an empty table and so reported "Secured" at every level; this version replaced it.
* **Clickjacking**: whether `X-Frame-Options` or a CSP `frame-ancestors` directive is present.
* **Data-at-rest**: a basic check that the stored value is not plaintext in the raw SQLite file. It does not assess key management, key storage, or operational security.

## Scope and limits

* Access control and privilege escalation are not tested; doing so needs an authenticated multi-user workflow (see paper Section 4.8).
* Latency numbers come from a single local development server and are exploratory, not an overhead estimate.
* The coverage values are binary (one end-to-end attack per class), not per-control fractions.
