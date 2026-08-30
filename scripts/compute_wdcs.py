"""
Computes REAL WDCS scores (paper Algorithm 1) from the JSON files produced
by run_attack_tests.py, instead of the illustrative Ci values in the
paper's worked example.

Usage (after running run_attack_tests.py for each level):

    python scripts/compute_wdcs.py \
        attack_results_baseline.json \
        attack_results_headers.json \
        attack_results_sanitization.json \
        attack_results_full.json

Note: this script scores the 5 classes the test kit actually exercises
(XSS, CSRF, SQLi, Clickjacking, Cryptographic exposure). Access-control
failure is left out, exactly as it is left out of run_attack_tests.py --
see that file's docstring for why.
"""
import json
import sys

# Same CVSS-derived severity weights used in the paper's worked example
# (Section "Applying WDCS to the Study's Own Results"), restricted to the
# 5 classes this kit measures.
SEVERITY = {
    "xss": 0.90,
    "csrf": 0.80,
    "sqli": 0.90,
    "clickjacking": 0.65,
    "data_at_rest": 0.75,
}

SECURED_LABELS = {
    "xss": "Secured",
    "csrf": "Secured",
    "sqli": None,  # checked via startswith below (message includes detail)
    "clickjacking": None,
    "data_at_rest": None,
}


def is_secured(class_key, entry):
    outcome = entry["outcome"]
    if class_key in ("xss", "csrf"):
        return outcome == "Secured"
    return outcome.startswith("Secured")


def score_file(path):
    with open(path) as f:
        data = json.load(f)

    weighted_sum = 0.0
    severity_total = 0.0
    per_class = {}
    for class_key, weight in SEVERITY.items():
        entry = data[class_key]
        ci = 1.0 if is_secured(class_key, entry) else 0.0
        weighted_sum += weight * ci
        severity_total += weight
        per_class[class_key] = ci

    wdcs = weighted_sum / severity_total if severity_total else 0.0
    return data["security_level"], wdcs, per_class


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    print(f"{'Configuration':<28}{'WDCS':<10}Per-class Ci")
    print("-" * 70)
    for path in sys.argv[1:]:
        level, wdcs, per_class = score_file(path)
        ci_str = ", ".join(f"{k}={v:.0f}" for k, v in per_class.items())
        print(f"{level:<28}{wdcs:<10.2f}{ci_str}")


if __name__ == "__main__":
    main()
