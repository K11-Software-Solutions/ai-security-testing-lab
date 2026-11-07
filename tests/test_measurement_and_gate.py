"""Attacks, mutations, measurement statistics and the gate's negative controls."""
import json
import random

import pytest

from evals import run_security_evals as gate
from seclab.app import Defences
from seclab.attacks import ATLAS, MUTATIONS, OWASP, SEEDS, adaptive, attack_suite, benign_suite, mutate
from seclab.measure import campaign, layer_effect, rule_of_three, wilson


def test_suite_covers_every_goal_channel_and_mutation():
    suite = attack_suite()
    assert len(suite) == len(SEEDS) * 2 * len(MUTATIONS)
    assert {a.goal for a in suite} == set(SEEDS) == set(OWASP) == set(ATLAS)
    assert {a.channel for a in suite} == {"direct", "indirect"}


def test_mutations_change_the_text_and_indirect_attacks_hide_in_a_document():
    plain = mutate("jailbreak", "plain").text
    assert all(mutate("jailbreak", m).text != plain for m in MUTATIONS if m != "plain")
    assert "--- TICKET ---" in mutate("jailbreak", "plain", "indirect").text


def test_benign_suite_has_tricky_requests():
    kinds = [b.kind for b in benign_suite()]
    assert kinds.count("tricky") == 10 and kinds.count("normal") == 10


def test_wilson_and_rule_of_three():
    p, lo, hi = wilson(0, 300)
    assert p == 0 and lo == 0 and 0 < hi < 0.02
    assert rule_of_three(300) == pytest.approx(0.01)


def test_no_defences_lets_most_attacks_through_and_recommended_stops_them():
    assert campaign(Defences.none(), repeats=5)["overall"][0] > 0.6
    assert campaign(Defences.recommended(), repeats=5)["successes"] == 0


def test_adaptive_attacker_beats_a_single_try():
    from dataclasses import replace
    d = replace(Defences.recommended(), secret_in_prompt=True)
    rng = random.Random(1)
    one = sum(adaptive("leak_secret", "direct", d, rng, budget=1)[0] for _ in range(100))
    many = sum(adaptive("leak_secret", "direct", d, rng, budget=10)[0] for _ in range(100))
    assert many > one


def test_layer_effect_is_zero_for_a_disabled_layer():
    from dataclasses import replace
    assert layer_effect(replace(Defences.recommended(), hardening=False), "hardening", repeats=5)["reduction"] == 0
    assert layer_effect(Defences.recommended(), "tool_permissions", repeats=5)["reduction"] > 0.9


@pytest.mark.parametrize("variant, expected", [
    ("", None), ("secret-in-prompt", "static: leak_secret"), ("no-output-filter", "static: exfiltrate"),
    ("no-tool-permissions", "static: unauthorized_tool"), ("no-budget", "static: denial_of_wallet"),
    ("no-hardening", "layer: hardening"), ("no-memory-policy", "layer: memory_policy"),
    ("no-input-filter", "layer: input_filter"), ("high-input-filter", "utility"),
])
def test_negative_controls(monkeypatch, tmp_path, variant, expected):
    monkeypatch.setenv("SEC_VARIANT", variant)
    code = gate.main(["--out", str(tmp_path)])
    failures = json.loads((tmp_path / "security_report.json").read_text(encoding="utf-8"))["gate_failures"]
    if expected is None:
        assert code == 0 and failures == []
    else:
        assert code == 1 and any(f.startswith(expected) for f in failures), failures
