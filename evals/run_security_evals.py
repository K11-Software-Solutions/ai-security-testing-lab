"""Security gate: attack campaigns, an adaptive attacker, layer-by-layer checks and the cost to real users.

Usage (from the repo root):

    python -m evals.run_security_evals                           # the recommended configuration
    SEC_VARIANT=no-output-filter python -m evals.run_security_evals  # a weakened configuration: must FAIL

Checks (thresholds in evals/thresholds.json):
  static      the full attack suite (6 goals x 2 channels x 6 mutations) repeated 20 times:
              no successes for any goal; the report gives the 95% upper bound on the true rate
  adaptive    an attacker with 10 tries per goal and channel, 20 times: no successes
  layers      each defence layer ON ITS OWN must cut success on the attacks it exists for by a
              minimum share, so a layer that silently stops working fails the build even when
              the other layers still hide it end to end
  utility     legitimate requests refused or altered, within limits

Writes evals/results/security_report.md and .json.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import replace
from pathlib import Path

from seclab.app import Defences
from seclab.attacks import ATLAS, OWASP
from seclab.measure import LAYER_TARGETS, adaptive_campaign, campaign, layer_effect, rule_of_three, utility

HERE = Path(__file__).parent
R = Defences.recommended()
VARIANTS = {
    "": R,
    "secret-in-prompt": replace(R, secret_in_prompt=True),
    "no-output-filter": replace(R, output_filter=False),
    "no-tool-permissions": replace(R, tool_permissions=False),
    "no-budget": replace(R, budget=False),
    "no-hardening": replace(R, hardening=False),
    "no-memory-policy": replace(R, memory_policy=False),
    "no-input-filter": replace(R, input_filter="off"),
    "high-input-filter": replace(R, input_filter="high"),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-gate", action="store_true")
    parser.add_argument("--out", type=Path, default=HERE / "results")
    args = parser.parse_args(argv)
    name = os.environ.get("SEC_VARIANT", "")
    if name not in VARIANTS:
        raise SystemExit(f"unknown SEC_VARIANT '{name}'; choose from {', '.join(v for v in VARIANTS if v)}")
    d = VARIANTS[name]
    t = json.loads((HERE / "thresholds.json").read_text(encoding="utf-8"))

    static = campaign(d, repeats=t["static_repeats"])
    adaptive = adaptive_campaign(d, budget=t["adaptive_budget"], trials=t["adaptive_trials"])
    layers = {layer: layer_effect(d, layer) for layer in LAYER_TARGETS}
    use = utility(d)

    failures = []
    per_goal_n = static["attempts"] // len(static["by_goal"])
    for goal, (p, lo, hi) in static["by_goal"].items():
        if round(p * per_goal_n) > t["max_static_successes"]:
            failures.append(f"static: {goal} succeeded {round(p * per_goal_n)} of {per_goal_n} times")
    for goal, (p, lo, hi) in adaptive.items():
        if p > 0:
            failures.append(f"adaptive: {goal} succeeded in {p:.0%} of attacker runs ({t['adaptive_budget']} tries each)")
    for layer, e in layers.items():
        need = t["min_layer_reduction"][layer]
        if e["reduction"] < need:
            failures.append(f"layer: {layer} on its own cuts its target attacks by {e['reduction']:.0%} (needs {need:.0%})")
    if use["false_refusal_rate"] > t["max_false_refusal_rate"]:
        failures.append(f"utility: {use['false_refusal_rate']:.0%} of legitimate requests refused")
    if use["altered_rate"] > t["max_altered_rate"]:
        failures.append(f"utility: {use['altered_rate']:.0%} of legitimate answers altered")

    ci = lambda w: f"{w[0]:.3f} ({w[1]:.3f}-{w[2]:.3f})"
    L = [f"# Security report: {name or 'recommended configuration'}", "",
         f"Static suite: {static['successes']} successes in {static['attempts']} attempts; "
         f"95% upper bound on the true rate {static['overall'][2]:.2%} (rule of three: {rule_of_three(static['attempts']):.2%}).", "",
         "| Goal | OWASP LLM | MITRE ATLAS | Static success (95% CI) | Adaptive attacker success (95% CI) |", "|---|---|---|---|---|"]
    for goal in static["by_goal"]:
        L.append(f"| {goal} | {OWASP[goal]} | {ATLAS[goal]} | {ci(static['by_goal'][goal])} | {ci(adaptive[goal])} |")
    L += ["", "## Each layer on its own", "", "| Layer | Target attacks succeed with no defences | ...with only this layer | Reduction | Required |",
          "|---|---|---|---|---|"]
    for layer, e in layers.items():
        L.append(f"| {layer} | {e['without']:.0%} | {e['alone']:.0%} | {e['reduction']:.0%} | {t['min_layer_reduction'][layer]:.0%} |")
    L += ["", "## Which layer stopped each attack (static suite)", "", "| Outcome | Attempts |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in sorted(static["stopped_by"].items(), key=lambda kv: -kv[1])]
    L += ["", f"Legitimate requests: {use['false_refusal_rate']:.0%} refused (of the tricky ones: {use['tricky_refused']:.0%}), "
          f"{use['altered_rate']:.0%} altered by the output filter.", "",
          "## Gate", "", "PASSED" if not failures else "FAILED:\n" + "\n".join(f"- {f}" for f in failures), ""]
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "security_report.md").write_text("\n".join(L), encoding="utf-8")
    (args.out / "security_report.json").write_text(json.dumps({"variant": name, "static": static, "adaptive": adaptive,
                                                              "layers": layers, "utility": use, "gate_failures": failures},
                                                             indent=2), encoding="utf-8")
    print("\n".join(L))
    if failures and not args.no_gate:
        print("Security gate FAILED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
