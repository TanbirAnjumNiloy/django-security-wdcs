"""
wdcs_tradeoff_sensitivity.py
-----------------------------
Companion to wdcs_sensitivity.py (same repository).

PURPOSE
    wdcs_sensitivity.py perturbs the severity weights (Si) over the four
    MEASURED configuration layers. Those layers are nested: every layer
    only adds controls, so Ci never decreases from one layer to the next.
    For such configurations the ranking is guaranteed by the monotonicity
    proof (paper, Section 4.3), and a 100% preservation rate is expected.

    This script asks the harder question raised in peer review: what
    happens when two configurations TRADE OFF protection between classes
    (one class improves while another regresses)? Here the ranking does
    depend on the weights, and this script quantifies how much.

IMPORTANT - WHAT IS AND IS NOT MEASURED
    The trade-off configurations below are SYNTHETIC SCENARIOS built from
    the same five vulnerability classes and the same Si values as the
    paper. They are NOT attack-test results and were NOT run against the
    Django application. Only the "Headers-only" reference vector is a
    measured result (paper, Table 7). The scenarios illustrate how the
    scoring function behaves; they make no claim about any real deployment.

    The script also reports how often a CI gate threshold (e.g. WDCS >= 0.80)
    gives a different pass/fail decision on the MEASURED layers when the
    weights are perturbed.

HOW TO RUN
    python wdcs_tradeoff_sensitivity.py
    (Python standard library only; fixed seed, output is reproducible.)
"""

import random

CLASSES = ["XSS", "CSRF", "SQL Injection", "Clickjacking", "Cryptographic exposure"]

# Severity weights Si (paper, Table 7).
SI_BASE = {
    "XSS": 0.90,
    "CSRF": 0.80,
    "SQL Injection": 0.90,
    "Clickjacking": 0.65,
    "Cryptographic exposure": 0.75,
}

# Measured coverage vectors (paper, Table 7).
MEASURED = {
    "Baseline":     [0, 1, 0, 0, 0],
    "Headers-only": [0, 1, 1, 1, 0],
    "Sanitization": [1, 1, 1, 1, 0],
    "Full":         [1, 1, 1, 1, 1],
}

# Synthetic trade-off scenarios (NOT measured). Vector order = CLASSES.
SCENARIOS = {
    # XSS sanitization added, but a refactor reintroduces an interpolated raw query.
    "S1: XSS fixed, SQLi regressed":        [1, 1, 0, 1, 0],
    # Field encryption added, but a middleware change drops framing protection.
    "S2: Encryption added, framing lost":   [0, 1, 1, 0, 1],
    # XSS sanitization added, but cookie settings break CSRF protection.
    "S3: XSS fixed, CSRF regressed":        [1, 0, 1, 1, 0],
}
REFERENCE = "Headers-only"  # scenarios are compared against this measured layer


def wdcs(weights, coverage):
    num = sum(weights[c] * ci for c, ci in zip(CLASSES, coverage))
    den = sum(weights[c] for c in CLASSES)
    return num / den


def perturb(rng, delta):
    return {c: min(1.0, max(0.1, SI_BASE[c] + rng.uniform(-delta, delta))) for c in CLASSES}


def random_weights(rng):
    return {c: rng.uniform(0.1, 1.0) for c in CLASSES}


def tradeoff_table(n_trials=20000, seed=7):
    rng = random.Random(seed)
    ref_vec = MEASURED[REFERENCE]
    print("=== Trade-off scenarios vs. measured reference:", REFERENCE, "===")
    print(f"{'Scenario':38s} {'WDCS@paper':>10s} {'ref@paper':>10s} {'P(>ref) +/-0.10':>16s} "
          f"{'P(>ref) +/-0.20':>16s} {'P(>ref) any w':>14s}")
    for name, vec in SCENARIOS.items():
        s0 = wdcs(SI_BASE, vec)
        r0 = wdcs(SI_BASE, ref_vec)
        row = [s0, r0]
        for delta in (0.10, 0.20):
            wins = 0
            for _ in range(n_trials):
                w = perturb(rng, delta)
                if wdcs(w, vec) > wdcs(w, ref_vec):
                    wins += 1
            row.append(wins / n_trials)
        wins = 0
        for _ in range(n_trials):
            w = random_weights(rng)
            if wdcs(w, vec) > wdcs(w, ref_vec):
                wins += 1
        row.append(wins / n_trials)
        print(f"{name:38s} {row[0]:10.4f} {row[1]:10.4f} {row[2]:16.3f} {row[3]:16.3f} {row[4]:14.3f}")
    print()


def pairwise_s2_s3(n_trials=20000, seed=11):
    rng = random.Random(seed)
    a, b = SCENARIOS["S2: Encryption added, framing lost"], SCENARIOS["S3: XSS fixed, CSRF regressed"]
    print("=== S2 vs S3 (two trade-off configurations compared directly) ===")
    print(f"WDCS at paper weights: S2={wdcs(SI_BASE, a):.4f}, S3={wdcs(SI_BASE, b):.4f}")
    for delta in (0.10, 0.20):
        wins = sum(1 for _ in range(n_trials) if wdcs(w := perturb(rng, delta), a) > wdcs(w, b))
        print(f"P(S2 > S3) with +/-{delta:.2f} weight perturbation: {wins / n_trials:.3f}")
    print()


def monotone_check(n_trials=20000, seed=3):
    """Measured layers are nested, so ordering must hold even for ANY positive weights."""
    rng = random.Random(seed)
    order = ["Baseline", "Headers-only", "Sanitization", "Full"]
    ok = 0
    for _ in range(n_trials):
        w = random_weights(rng)
        vals = [wdcs(w, MEASURED[k]) for k in order]
        if vals[0] <= vals[1] <= vals[2] <= vals[3]:
            ok += 1
    print("=== Measured (nested) layers under ANY positive weights in [0.1, 1.0] ===")
    print(f"Order preserved: {ok}/{n_trials}\n")


def threshold_gate(n_trials=20000, seed=5, thresholds=(0.60, 0.80, 0.90)):
    rng = random.Random(seed)
    print("=== CI gate sensitivity on MEASURED layers (weights +/-0.10) ===")
    print("Share of weight draws in which the layer scores >= threshold")
    print(f"{'Layer':14s} " + " ".join(f">={t:.2f}".rjust(8) for t in thresholds))
    for layer, vec in MEASURED.items():
        counts = [0] * len(thresholds)
        for _ in range(n_trials):
            w = perturb(rng, 0.10)
            s = wdcs(w, vec)
            for i, t in enumerate(thresholds):
                if s >= t:
                    counts[i] += 1
        print(f"{layer:14s} " + " ".join(f"{c / n_trials:8.3f}" for c in counts))
    print()


if __name__ == "__main__":
    monotone_check()
    tradeoff_table()
    pairwise_s2_s3()
    threshold_gate()
