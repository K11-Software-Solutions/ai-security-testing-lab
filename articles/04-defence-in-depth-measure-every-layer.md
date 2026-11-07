# 04. Defence in Depth: Measure Every Layer

> **Series:** AI Security Testing Lab · [Index](../README.md#articles) · Previous: [03](03-the-attack-library.md) · Next: [05. Adaptive Attackers and What Zero Proves](05-adaptive-attackers-and-what-zero-proves.md)

"Defence in depth" means no single layer has to be perfect. It also means a layer can stop working and **nothing visible changes**, because another layer catches the same attacks. A security test has to be able to tell which layer is doing the work.

## Experiment E2

The static suite (1,440 attempts) against each layer alone, all layers, and all layers but one:

| Configuration | Attack success | Goals still succeeding |
|---|---|---|
| no defences | 72.7% | all six |
| only input filter | 47.5% | all six |
| only hardening | 29.8% | all six |
| only output filter | 31.0% | leak, tool misuse, cost |
| only tool permissions, memory policy, budget or secret out of the prompt | 59% to 61% | every goal but their own |
| **all layers (recommended)** | **0%** | none |
| all but input filter | 0% | none |
| all but hardening | 0% | none |
| all but memory policy | 0% | none |
| all but tool permissions | 3.1% | tool misuse |
| all but output filter | 5.3% | exfiltration, jailbreak |
| all but budget | 4.3% | cost |
| all but secret out of the prompt | 1.6% | secret leak |

## What it shows

**Two kinds of layer.** The input filter and hardening reduce attacks *broadly but partially*: alone, they leave 30% to 48% of attacks succeeding, across every goal. Tool permissions, the memory policy, the output filter, the budget and keeping the secret out of the prompt each stop *one kind of harm completely*, and do nothing for the others. They are deterministic code that checks what the model is about to do, so a fooled model is still stopped.

**Some harms have exactly one defence.** Remove tool permissions and unauthorised emails come back; nothing else stops them. The same for the output filter (exfiltration and jailbreak output), the budget (cost) and the secret. These are the layers to test hardest.

**Some layers are invisible end to end.** Removing the input filter, hardening or the memory policy changed nothing in the end-to-end result, because the deterministic layers caught everything they would have caught. That does **not** mean they are useless: they reduce how often the last line of defence is tested, and they matter for attacks this suite does not contain. It means an end-to-end gate **cannot tell whether they work**.

## Testing each layer on its own

The gate therefore runs a second check: each layer **alone**, against no defences, must cut the attacks it exists for by a minimum share:

| Layer alone | Reduction on its target attacks | Required |
|---|---|---|
| input filter (low) | 38% | 25% |
| hardening | 60% | 40% |
| tool permissions, memory policy, output filter, budget, no secret in prompt | 100% | 90% |

With this check, switching off the input filter, hardening or the memory policy **fails the build**, even though the end-to-end attack success stays at zero. The negative controls in CI prove it (article 08).

This is the same idea as testing a backup system by failing the primary: you have not tested a fallback until you have watched it work on its own.

## Attribution

The report also counts which layer stopped each attempt in the static suite. In the recommended configuration: the model (helped by hardening) refused 690, the input filter blocked 480, the output filter 77, the budget 62, tool permissions 45, the memory policy 44, and keeping the secret out of the prompt left nothing to leak in 42. The attribution makes a layer's silent failure visible as a shift in these counts, before it becomes a breach.

## Takeaways

- **Defence in depth hides broken layers.** End-to-end results cannot show them.
- **Test every layer on its own**, against the attacks it exists for, and gate on it.
- **Find the harms with only one defence**, and test those layers hardest.
- **Deterministic checks on actions beat filters on words**: they still work when the model is fooled.
