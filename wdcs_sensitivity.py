"""
wdcs_sensitivity.py
--------------------
Monte Carlo weight-robustness (sensitivity) analysis for the Weighted
Defense Coverage Score (WDCS).

WHAT THIS SCRIPT DOES
    It answers one question: if a reviewer disagrees with the exact
    CVSS-derived severity weights (Si) used in the paper, does the
    paper's main empirical finding -- that measured coverage strictly
    improves from Baseline to Full across the four hardening layers --
    still hold?

    It does this by redrawing each class's severity weight thousands
    of times within a plausible uncertainty band (+/- 1.0 CVSS point)
    and recomputing WDCS every time, using ONLY the already-verified
    Ci coverage values from the paper's empirical harness (Table 5).

WHAT THIS SCRIPT DOES NOT DO
    It does not run any attack, exploit, or new experiment against the
    Django application. The Ci matrix below is copied directly from
    the paper's Table 5 (itself derived from Table 4's real, script-
    verified attack-test outcomes). This script only perturbs the
    weights (Si), not the coverage data (Ci) -- it is a sensitivity
    analysis of the *scoring function*, not a new security test.

HOW TO RUN
    python wdcs_sensitivity.py

    Requires only the Python standard library (no dependencies).
    The random seed is fixed (42) so the output below is exactly
    reproducible.

OUTPUT
    1. WDCS under the paper's original CVSS-derived weights.
    2. WDCS under uniform weights (a naive alternative), for comparison.
    3. A 5,000-trial Monte Carlo sweep: for each of the four hardening
       layers, the mean, 95% interval, and min/max WDCS across all
       weight perturbations.
    4. A monotonicity check: across all 5,000 trials, how often the
       measured ordering Baseline <= Headers-only <= Sanitization <=
       Full is preserved.

Author: Tanvir Mahatab Niloy
Companion script for: "WDCS Revisited: A Weight-Robust, Verifiable
Coverage Metric for Tracking Django Security Posture"
Repository: https://github.com/TanbirAnjumNiloy/django-security-wdcs
"""

import random
import statistics


# ---------------------------------------------------------------------
# 1. Ground-truth data (copied verbatim from the paper's Table 5).
#    Si  = CVSS-derived severity weight, normalized to [0, 1].
#    Ci  = coverage ratio per class per configuration layer, taken
#          directly from the empirical, attack-tested results in
#          Table 4 (1 = Secured, 0 = Vulnerable).
# ---------------------------------------------------------------------

CLASSES = ["XSS", "CSRF", "SQL Injection", "Clickjacking", "Cryptographic exposure"]

SI_BASELINE = {
    "XSS": 0.90,
    "CSRF": 0.80,
    "SQL Injection": 0.90,
    "Clickjacking": 0.65,
    "Cryptographic exposure": 0.75,
}

CI_BY_LAYER = {
    "Baseline":     {"XSS": 0, "CSRF": 1, "SQL Injection": 0, "Clickjacking": 0, "Cryptographic exposure": 0},
    "Headers-only": {"XSS": 0, "CSRF": 1, "SQL Injection": 1, "Clickjacking": 1, "Cryptographic exposure": 0},
    "Sanitization": {"XSS": 1, "CSRF": 1, "SQL Injection": 1, "Clickjacking": 1, "Cryptographic exposure": 0},
    "Full":         {"XSS": 1, "CSRF": 1, "SQL Injection": 1, "Clickjacking": 1, "Cryptographic exposure": 1},
}

LAYER_ORDER = ["Baseline", "Headers-only", "Sanitization", "Full"]


# ---------------------------------------------------------------------
# 2. The WDCS formula itself (Algorithm 1 in the paper).
# ---------------------------------------------------------------------

def wdcs(severity_weights: dict, coverage: dict) -> float:
    """Compute WDCS = sum(Si * Ci) / sum(Si) for one configuration layer."""
    numerator = sum(severity_weights[c] * coverage[c] for c in CLASSES)
    denominator = sum(severity_weights[c] for c in CLASSES)
    return numerator / denominator


# ---------------------------------------------------------------------
# 3. Baseline (paper) weights vs. a naive uniform-weight scheme.
# ---------------------------------------------------------------------

def print_fixed_weight_scores(title: str, weights: dict) -> None:
    print(f"=== {title} ===")
    for layer in LAYER_ORDER:
        score = wdcs(weights, CI_BY_LAYER[layer])
        print(f"  {layer:15s} WDCS = {score:.4f}")
    print()


# ---------------------------------------------------------------------
# 4. Monte Carlo weight-perturbation sweep.
# ---------------------------------------------------------------------

def run_monte_carlo(n_trials: int = 5000, delta: float = 0.10, seed: int = 42) -> dict:
    """
    Redraw each class's severity weight n_trials times, uniformly within
    [Si - delta, Si + delta] (clipped to [0.1, 1.0]), and recompute WDCS
    for every hardening layer on each draw.

    delta = 0.10 on the normalized [0, 1] scale corresponds to roughly
    +/- 1.0 CVSS point on the original 0-10 scale.
    """
    random.seed(seed)
    results = {layer: [] for layer in LAYER_ORDER}

    for _ in range(n_trials):
        perturbed = {
            c: min(1.0, max(0.1, SI_BASELINE[c] + random.uniform(-delta, delta)))
            for c in CLASSES
        }
        for layer in LAYER_ORDER:
            results[layer].append(wdcs(perturbed, CI_BY_LAYER[layer]))

    return results


def summarize(results: dict, n_trials: int) -> None:
    print(f"=== Monte Carlo sensitivity (N={n_trials}, Si +/- 0.10 normalized "
          f"\u2248 +/- 1.0 CVSS point) ===")
    print(f"{'Layer':15s} {'Mean':>8s} {'95% Range':>20s} {'Min':>8s} {'Max':>8s}")
    for layer in LAYER_ORDER:
        vals = sorted(results[layer])
        n = len(vals)
        mean = statistics.mean(vals)
        lo = vals[int(0.025 * n)]
        hi = vals[int(0.975 * n) - 1]
        print(f"{layer:15s} {mean:8.4f} {'[' + f'{lo:.4f}, {hi:.4f}' + ']':>20s} "
              f"{min(vals):8.4f} {max(vals):8.4f}")
    print()


def check_monotonicity(results: dict, n_trials: int) -> None:
    preserved = 0
    for i in range(n_trials):
        b = results["Baseline"][i]
        h = results["Headers-only"][i]
        s = results["Sanitization"][i]
        f = results["Full"][i]
        if b <= h <= s <= f:
            preserved += 1

    pct = 100 * preserved / n_trials
    print("=== Monotonicity check across all trials ===")
    print(f"Baseline <= Headers-only <= Sanitization <= Full preserved in "
          f"{preserved}/{n_trials} trials ({pct:.2f}%)")
    print()


# ---------------------------------------------------------------------
# 5. Entry point.
# ---------------------------------------------------------------------

def main() -> None:
    print_fixed_weight_scores("CVSS-derived weights (paper, Table 5)", SI_BASELINE)

    uniform_weights = {c: 0.80 for c in CLASSES}
    print_fixed_weight_scores("Uniform weights (Si = 0.80 for all classes, "
                               "for comparison)", uniform_weights)

    n_trials = 5000
    results = run_monte_carlo(n_trials=n_trials, delta=0.10, seed=42)
    summarize(results, n_trials)
    check_monotonicity(results, n_trials)


if __name__ == "__main__":
    main()
