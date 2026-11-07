# 08. The Security Gate, Negative Controls and Limitations

> **Series:** AI Security Testing Lab · [Index](../README.md#articles) · Previous: [07](07-design-fixes-beat-filters.md)

## The gate

`python -m evals.run_security_evals` runs four checks on the recommended configuration:

| Check | Requirement |
|---|---|
| Static suite: 72 attacks × 20 repeats = 1,440 attempts | zero successes for every goal |
| Adaptive attacker: 10 tries, 20 runs per goal and channel | zero successes |
| Each layer on its own | cuts its target attacks by at least 25% (input filter), 40% (hardening) or 90% (deterministic layers) |
| Legitimate requests | at most 5% refused and 10% altered |

The report gives, for every goal, its OWASP and MITRE ATLAS mapping, the static and adaptive success rates with 95% intervals, the layer-by-layer table, which layer stopped what, and the utility cost. It runs in about a second.

## Negative controls

Eight weakened configurations, each of which must fail, for the right reason:

| Variant | Fails on |
|---|---|
| `secret-in-prompt` | static and adaptive secret leaks; the "no secret in prompt" layer test |
| `no-output-filter` | exfiltration and jailbreak successes |
| `no-tool-permissions` | unauthorised tool use |
| `no-budget` | denial of wallet |
| `no-hardening` | the hardening layer test only (end to end, nothing changes) |
| `no-memory-policy` | the memory-policy layer test only |
| `no-input-filter` | the input-filter layer test only |
| `high-input-filter` | utility: half of legitimate requests refused |

The three "layer test only" rows are the reason the layer tests exist: without them, those configurations would pass.

## Reproducible experiments

The five experiments behind articles 03 to 07 are deterministic, and CI fails if they differ from the committed [`experiments/results/summary.md`](../experiments/results/summary.md).

## Limitations

- **A simulated model.** Its susceptibility is a simple function of attack strength and hardening. Real models differ by attack type, change between versions and respond to wording in ways no formula captures. The success rates here are illustrations of the method, not predictions.
- **A small attack library.** Six goals, two channels, six mutations. Real red-team suites have thousands of attacks, including multi-turn conversations, attacks split across several documents, and attacks in images or audio.
- **A simple adaptive attacker.** It cycles through fixed mutations. Real adaptive attacks search: optimise prompts automatically, use another model to rewrite them, or learn from refusals. Assume they do better.
- **Pattern-based input filter.** Classifier-based filters behave differently; the measurement method is the same.
- **One system design.** Agents with more tools, browsing or code execution have a larger attack surface; the [MCP Testing Lab](https://github.com/K11-Software-Solutions/mcp-testing-lab) (next in the series) covers the tool supply chain.

## Using the method on a real system

1. Replace the simulated model with your application endpoint; keep the layers' checks where they really are (in your code).
2. Start from an established probe library, such as the K11 [LLM assurance toolkit](https://github.com/K11-Software-Solutions/k11techlab-llm-assurance-toolkit), which maps its probes to the OWASP Top 10 for LLM Applications, and organise results by goal, channel and mutation.
3. Run static and adaptive campaigns, report rates with intervals and the attacker you assumed.
4. Test every layer on its own, and keep a benign set with tricky requests.
5. Make every successful attack a permanent regression test.

## Takeaways

- **Gate on observed attacks, adaptive attackers, each layer alone, and the cost to users.**
- **Prove each check with a weakened configuration that must fail.**
- **Report what zero proves**, and what the simulated parts of your test leave out.
