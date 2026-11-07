# 05. Adaptive Attackers and What "Zero Successes" Proves

> **Series:** AI Security Testing Lab · [Index](../README.md#articles) · Previous: [04](04-defence-in-depth-measure-every-layer.md) · Next: [06. Guardrails Have a Price](06-guardrails-have-a-price.md)

Two statements appear in almost every AI red-team report: "we tested N attacks" and "none succeeded". This article is about what those statements are worth.

## The attacker keeps trying

Experiment E1 uses a configuration with every defence on except one weakness: the secret is still in the system prompt. On the static suite, secret-leak attacks succeed 9.6% of the time. Then an **adaptive attacker** tries mutation after mutation (plain, split, base64, translated, role-play, paraphrase, and round again) until the secret leaks or the budget runs out. 100 runs per channel:

| Attacker's tries | Secret leaked in |
|---|---|
| 1 | 0% |
| 3 | 26% |
| 6 | 44% |
| 10 | 55% |
| 30 | **90%** |

On a single try, nothing leaks: the first attempt is the textbook attack, and the input filter catches it. A test that stopped there would report the system as safe. Given ten tries, an attacker succeeds more often than not; given thirty, almost always. The weakness was always there; a static suite measures how often a *random* attacker finds it, and an adaptive one measures how reliably a *motivated* attacker does.

**Report both.** A static success rate tells you about exposure to casual and automated attacks. An adaptive success rate with a stated budget tells you about a determined attacker. Neither replaces the other.

## What zero proves

Suppose a test runs *n* attacks and none succeeds. The true success rate is not zero; it is somewhere between zero and an upper bound. For 95% confidence, a good approximation is the **rule of three**: the upper bound is about 3/*n*.

Experiment E3 turns it around: if the true rate is small but not zero, how likely is a test to see no successes at all?

| Attempts, 0 successes | 95% upper bound | Chance of seeing 0 if the true rate is 0.5% | ...1% | ...2% |
|---|---|---|---|---|
| 30 | 10% | 86% | 74% | 55% |
| 100 | 3% | 61% | 37% | 13% |
| 300 | 1% | 22% | 5% | 0.2% |
| 1,000 | 0.3% | 1% | ~0% | ~0% |
| 3,000 | 0.1% | ~0% | ~0% | ~0% |

A 30-attack red-team exercise that finds nothing would also find nothing **three times in four** against a system that fails 1% of the time. If the assistant handles 100,000 conversations a month, a 1% success rate is a thousand successful attacks.

## In the lab's gate

The gate runs 1,440 static attempts (240 per goal) and 40 adaptive attacker runs per goal, with zero successes allowed. The report states what that proves: an overall 95% upper bound of 0.27%, about 1.6% per goal, and 8.8% per goal for the adaptive runs. Those bounds, not "it passed", are what a security review should read.

## Practical rules

1. **State the attacker.** Static suite or adaptive, how many tries, which mutations.
2. **State the sample size, and the upper bound it supports**, every time you report zero.
3. **Size the test for the risk.** A harm that is unacceptable at 1 in 1,000 needs thousands of attempts to bound, or a design that removes it (article 07).
4. **Rotate and grow the attack set.** Static suites decay as models and attackers change; add every successful attack found anywhere to the suite.

## Takeaways

- **An adaptive attacker finds what a static suite samples.** Measure both.
- **"0 of n" means "probably below 3/n", not "safe".**
- **Small red-team exercises cannot see small but real risks.**
