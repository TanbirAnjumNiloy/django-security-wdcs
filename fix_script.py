import pathlib

p = pathlib.Path(r"C:\Users\searc\Desktop\django_test_kit\scripts\run_attack_tests.py")
text = p.read_text(encoding="utf-8")

old = '''def test_data_at_rest(base_url, db_path):
    # First, write a known secret through the app (legitimate write path).
    secret = "SENSITIVE-TEST-VALUE-42"
    r = requests.post(base_url + "/profile/save/",
                       data={"username": "dar_test_user", "note": secret}, timeout=5)
    row_id = r.json().get("id")'''

new = '''def test_data_at_rest(base_url, db_path):
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
    row_id = r.json().get("id")'''

if old not in text:
    print("PATCH_FAILED: old text not found")
else:
    p.write_text(text.replace(old, new), encoding="utf-8")
    print("PATCH_OK")