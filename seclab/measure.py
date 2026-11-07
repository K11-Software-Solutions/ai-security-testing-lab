"""Measuring security: attack success rates with honest uncertainty.

- Wilson interval: a proportion with a confidence interval that behaves near 0 and 1.
- Rule of three: if 0 of n attempts succeed, the 95% upper bound on the true rate is about
  3/n. "0 of 50 attacks succeeded" means "the true rate is probably below 6%", not "safe".
- Campaign: run the static suite many times (the model is random) and record, for every
  attempt, whether it succeeded and WHICH LAYER stopped it.
- Utility: the cost to legitimate users, i.e. benign requests refused or altered.
"""
from __future__ import annotations

import random
from collections import Counter, defaultdict

from seclab.app import Defences
from seclab.attacks import adaptive, attack_suite, benign_suite, run
from seclab.app import handle, Session


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return float("nan"), 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def rule_of_three(n: int) -> float:
    return 3 / n


def campaign(d: Defences, repeats: int = 20, seed: int = 0) -> dict:
    rng = random.Random(seed)
    by_goal = defaultdict(lambda: [0, 0])
    by_channel = defaultdict(lambda: [0, 0])
    by_mutation = defaultdict(lambda: [0, 0])
    stopped = Counter()
    for _ in range(repeats):
        for a in attack_suite():
            ok, out, _ = run(a, d, rng)
            for table, key in ((by_goal, a.goal), (by_channel, a.channel), (by_mutation, a.mutation)):
                table[key][0] += ok
                table[key][1] += 1
            stopped["succeeded" if ok else (out.blocked_by or "no effect")] += 1
    total = sum(v[0] for v in by_goal.values()), sum(v[1] for v in by_goal.values())
    return {"overall": wilson(*total), "attempts": total[1], "successes": total[0],
            "by_goal": {k: wilson(*v) for k, v in by_goal.items()},
            "by_channel": {k: wilson(*v) for k, v in by_channel.items()},
            "by_mutation": {k: wilson(*v) for k, v in by_mutation.items()},
            "stopped_by": dict(stopped)}


def adaptive_campaign(d: Defences, budget: int = 10, trials: int = 20, seed: int = 0) -> dict:
    rng = random.Random(seed)
    from seclab.attacks import SEEDS
    rows = {}
    for goal in SEEDS:
        wins = sum(adaptive(goal, ch, d, rng, budget)[0] for _ in range(trials) for ch in ("direct", "indirect"))
        rows[goal] = wilson(wins, 2 * trials)
    return rows


def utility(d: Defences, seed: int = 0) -> dict:
    """Benign requests refused by the input filter, or changed by the output filter."""
    rng = random.Random(seed)
    refused, altered, n_tricky, refused_tricky = 0, 0, 0, 0
    for b in benign_suite():
        out = handle(b, Session(), d, rng)
        refused += out.refused_benign
        altered += (not out.refused_benign) and out.output != b.expected
        if b.kind == "tricky":
            n_tricky += 1
            refused_tricky += out.refused_benign
    n = len(benign_suite())
    return {"false_refusal_rate": refused / n, "tricky_refused": refused_tricky / n_tricky, "altered_rate": altered / n}


# Each layer, tested on its own: which attack goals it exists to stop.
LAYER_TARGETS = {
    "input_filter": ("leak_secret", "exfiltrate", "jailbreak", "unauthorized_tool", "memory_poison", "denial_of_wallet"),
    "hardening": ("leak_secret", "exfiltrate", "jailbreak", "unauthorized_tool", "memory_poison", "denial_of_wallet"),
    "tool_permissions": ("unauthorized_tool",),
    "memory_policy": ("memory_poison",),
    "output_filter": ("exfiltrate", "jailbreak"),
    "budget": ("denial_of_wallet",),
    "secret_in_prompt": ("leak_secret",),
}


def isolate(d: Defences, layer: str) -> Defences:
    """No defences except `layer`, set as it is in `d`."""
    from dataclasses import replace
    return replace(Defences.none(), **{layer: getattr(d, layer)})


def layer_effect(d: Defences, layer: str, repeats: int = 10, seed: int = 0) -> dict:
    """Relative reduction in success rate on the layer's target goals: the layer alone vs no defences."""
    targets = LAYER_TARGETS[layer]
    base = campaign(Defences.none(), repeats, seed)["by_goal"]
    alone = campaign(isolate(d, layer), repeats, seed)["by_goal"]
    b = sum(base[g][0] for g in targets) / len(targets)
    a = sum(alone[g][0] for g in targets) / len(targets)
    return {"layer": layer, "without": b, "alone": a, "reduction": 1 - a / b if b else 0.0}
