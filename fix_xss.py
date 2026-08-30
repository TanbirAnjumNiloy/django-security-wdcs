import pathlib

p = pathlib.Path(r"C:\Users\searc\Desktop\django_test_kit\scripts\run_attack_tests.py")
text = p.read_text(encoding="utf-8")

old = '''def test_xss(base_url):
    payload = "<script>alert(document.cookie)</script>"
    r = requests.post(base_url + "/comment/", data={"content": payload}, timeout=5)
    reflected_unescaped = "<script>" in r.text
    return {
        "attack_class": "Reflected XSS",
        "payload": payload,
        "http_status": r.status_code,
        "script_tag_reflected_unescaped": reflected_unescaped,
        "outcome": "Vulnerable" if reflected_unescaped else "Secured",
        "response_body": r.text[:200],
    }'''

new = '''def test_xss(base_url):
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
    }'''

if old not in text:
    print("XSS_PATCH_FAILED")
else:
    p.write_text(text.replace(old, new), encoding="utf-8")
    print("XSS_PATCH_OK")