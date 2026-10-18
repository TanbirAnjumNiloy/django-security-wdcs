"""
Reproduces the paper's Table 6 (attack-test outcomes) with real, verifiable
outcomes, each saved with the exact payload and response as evidence.
Run against a live server:

    SECURITY_LEVEL=baseline python manage.py runserver 8001
    python scripts/run_attack_tests.py --level baseline --url http://127.0.0.1:8001 \
        --db /absolute/path/to/db.sqlite3

Repeat for headers / sanitization / full. The four JSON files are the raw
evidence behind Table 6 (exact payload, HTTP response, DB bytes).

Covers five vulnerability classes (XSS, CSRF, SQL Injection, Clickjacking,
Data-at-rest exposure).

What each check measures (so the labels are not over-read):
  * XSS          -- whether the payload is reflected UNESCAPED in the response
                    body. It does not execute the script in a browser, so a
                    Content-Security-Policy header does not change this result.
  * SQL Injection-- seed-then-inject: the test first writes a known row through
                    the app, confirms a normal lookup finds it (positive
                    control), and only then sends the injection payload. If the
                    seed or control fails the outcome is INCONCLUSIVE, never
                    "Secured". (An earlier version injected into an empty
                    table and reported "Secured" at every level.)
  * Data-at-rest -- a basic check that the stored value is not plaintext in the
                    raw SQLite file; it says nothing about key management.

Privilege escalation / access control is intentionally out of scope for this
minimal kit -- it needs a real authenticated-session flow, which is a
reasonable next extension but not something to fake here.
"""
import argparse
import json
import sqlite3
import sys

import requests


def test_xss(base_url):
    payload = "<script>alert(document.cookie)</script>"
    session = requests.Session()
    session.get(base_url + "/ping/", timeout=5)
    csrftoken = session.cookies.get("csrftoken", "")
    r = session.post(
        base_url + "/comment/",
        data={"content": payload},
        headers={"X-CSRFToken": csrftoken},
        timeout=5,
    )
    reflected_unescaped = "<script>" in r.text
    return {
        "attack_class": "Reflected XSS",
        "payload": payload,
        "http_status": r.status_code,
        "script_tag_reflected_unescaped": reflected_unescaped,
        "outcome": "Vulnerable" if reflected_unescaped else "Secured",
        "response_body": r.text[:200],
    }


def test_csrf(base_url):
    # POST with NO CSRF token/cookie at all -- what an off-site forged
    # form submission looks like.
    r = requests.post(base_url + "/profile/save/",
                       data={"username": "csrf_test_user", "note": "x"},
                       timeout=5)
    rejected = r.status_code == 403
    return {
        "attack_class": "CSRF",
        "payload": "POST with no CSRF token/cookie",
        "http_status": r.status_code,
        "outcome": "Secured" if rejected else "Vulnerable",
    }


def test_sqli(base_url):
    """Seed-then-inject SQL injection test with a positive control."""
    payload = "' OR '1'='1' --"
    seed_username = "sqli_seed_user"

    # 1) Seed: write a known row through the app's legitimate write path.
    session = requests.Session()
    session.get(base_url + "/ping/", timeout=5)
    csrftoken = session.cookies.get("csrftoken", "")
    seed = session.post(
        base_url + "/profile/save/",
        data={"username": seed_username, "note": "sqli-seed"},
        headers={"X-CSRFToken": csrftoken},
        timeout=5,
    )

    # 2) Positive control: a normal lookup for the seeded user must find it.
    control = requests.get(base_url + "/search/", params={"username": seed_username}, timeout=5)
    try:
        control_body = control.json()
    except ValueError:
        control_body = {"error": "non-JSON response", "raw": control.text[:200]}
    control_rows = control_body.get("row_count", 0) or 0

    # 3) Inject.
    r = requests.get(base_url + "/search/", params={"username": payload}, timeout=5)
    try:
        body = r.json()
    except ValueError:
        body = {"error": "non-JSON response", "raw": r.text[:200]}
    payload_rows = body.get("row_count", 0) or 0
    match_found = bool(body.get("match_found", False))

    if seed.status_code != 200 or control_rows < 1:
        outcome = "INCONCLUSIVE (seed or positive control failed; no table data to test against)"
    elif payload_rows > 0:
        outcome = f"Vulnerable (auth bypass: payload returned {payload_rows} row(s))"
    else:
        outcome = "Secured (payload returned 0 rows; positive control passed)"

    return {
        "attack_class": "SQL Injection",
        "payload": payload,
        "seed_http_status": seed.status_code,
        "control_row_count": control_rows,
        "http_status": r.status_code,
        "match_found": match_found,
        "payload_row_count": payload_rows,
        "outcome": outcome,
        "raw_response": body,
    }


def test_clickjacking(base_url):
    r = requests.get(base_url + "/frame-target/", timeout=5)
    xfo = r.headers.get("X-Frame-Options")
    csp = r.headers.get("Content-Security-Policy", "")
    framing_blocked = bool(xfo) or "frame-ancestors" in csp
    return {
        "attack_class": "Clickjacking",
        "x_frame_options_header": xfo,
        "content_security_policy_header": csp,
        "outcome": "Secured (frame blocked)" if framing_blocked else "Vulnerable (framing allowed)",
    }


def test_data_at_rest(base_url, db_path):
    # First, write a known secret through the app (legitimate write path).
    # Must include CSRF token because CsrfViewMiddleware is always on.
    secret = "SENSITIVE-TEST-VALUE-42"
    session = requests.Session()
    session.get(base_url + "/ping/", timeout=5)
    csrftoken = session.cookies.get("csrftoken", "")
    r = session.post(
        base_url + "/profile/save/",
        data={"username": "dar_test_user", "note": secret},
        headers={"X-CSRFToken": csrftoken},
        timeout=5,
    )
    if r.status_code != 200:
        return {
            "attack_class": "Data-at-rest exposure",
            "secret_written": secret,
            "http_status": r.status_code,
            "raw_response": r.text[:300],
            "outcome": "ERROR - could not write secret (status " + str(r.status_code) + ")",
        }
    row_id = r.json().get("id")

    # Then inspect the raw sqlite file directly, bypassing the ORM/
    # from_db_value() decrypt path entirely -- simulating "direct
    # inspection of a database dump".
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT sensitive_note FROM secapp_userprofile WHERE id = ?", (row_id,))
    row = cur.fetchone()
    conn.close()
    stored_value = row[0] if row else None
    plaintext_visible = stored_value == secret

    return {
        "attack_class": "Data-at-rest exposure",
        "secret_written": secret,
        "raw_db_bytes": stored_value,
        "outcome": "Vulnerable (plaintext visible)" if plaintext_visible else "Secured (ciphertext only)",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--level", required=True,
                         choices=["baseline", "headers", "sanitization", "full"])
    parser.add_argument("--url", default="http://127.0.0.1:8001")
    parser.add_argument("--db", required=True, help="Absolute path to db.sqlite3 for this run")
    args = parser.parse_args()

    results = {
        "security_level": args.level,
        "xss": test_xss(args.url),
        "csrf": test_csrf(args.url),
        "sqli": test_sqli(args.url),
        "clickjacking": test_clickjacking(args.url),
        "data_at_rest": test_data_at_rest(args.url, args.db),
    }

    print(json.dumps(results, indent=2))
    out_file = f"attack_results_{args.level}.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out_file} -- run all four levels, then diff the four "
          f"JSON files; they are the raw evidence behind the paper's Table 6.", file=sys.stderr)


if __name__ == "__main__":
    main()
