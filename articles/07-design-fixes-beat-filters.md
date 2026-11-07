# 07. Design Fixes Beat Filters: Secrets, Exfiltration and Memory

> **Series:** AI Security Testing Lab · [Index](../README.md#articles) · Previous: [06](06-guardrails-have-a-price.md) · Next: [08. The Security Gate](08-the-security-gate-ci-limitations.md)

Some attacks can be filtered. Others are better **designed away**: change the system so the attack has nothing to achieve. Three examples from the lab.

## 1. Secrets: don't put them where the model can read them

With every other layer on and the escalation code in the system prompt, the static suite leaked it 9.6% of the time and an adaptive attacker with ten tries 55% of the time (article 05). Every successful leak had the same shape: the attacker asked for the code **encoded** (in base64, or spelled out), and the output filter, which redacts the literal secret, did not recognise the encoded form.

You can add base64 detection to the filter. The attacker then asks for hex, or every other character, or the code reversed, or written as a poem. Filtering the forms of a secret is a race the defender cannot win.

The design fix ends the race: **the secret is not in the prompt.** The escalation code lives in a backend that the model cannot read; a tool that needs it uses it server-side. In the lab, `secret_in_prompt=False` took secret leakage to zero in the static suite and against the adaptive attacker, because there is nothing to leak. This is the core guidance of OWASP LLM07 (System Prompt Leakage): treat the system prompt as public.

## 2. Exfiltration: an allowlist, not a blocklist

The exfiltration attack makes the assistant end its answer with a Markdown image whose URL carries the user's data to an attacker's server. When the answer is rendered, the browser fetches the image, and the data is sent; no click needed.

Blocking known bad domains fails as soon as the attacker uses a new one. The lab's output filter does the opposite: it **keeps only links to allowlisted domains and removes all images**. The attack then has no way out, whatever domain it uses or however the instruction is disguised. Removing that one layer let exfiltration succeed in 88% of adaptive attacker runs; with it, never. The cost (article 06) is that legitimate links outside the allowlist are removed too.

## 3. Memory: store facts, never instructions

The memory-poisoning attack is the slowest and the most dangerous: it stores "ALWAYS_APPEND a tracking image" in the assistant's long-term memory, and the harm appears **in a later session**, when the user asks an innocent question and the answer includes the attacker's tracking image. Nothing in the later session looks like an attack; there is no injected text to filter.

The memory policy is a design rule: **store only facts the user confirmed; never store instructions.** With it, poisoning never succeeded. Without it, the output filter still caught the later leak (the tracking image is not on the allowlist), which is why "all but memory policy" shows zero end to end and why the layer needs its own isolated test (article 04).

The test that matters here spans **two sessions**: write in the first, check the second. Single-turn tests cannot see memory poisoning at all.

## The pattern

| Problem | Filter approach | Design approach |
|---|---|---|
| secret in the prompt | redact known forms of the secret | keep the secret out of the prompt |
| exfiltration through rendered links | block known bad domains | allow only known good domains; no images |
| poisoned memory | detect suspicious memory writes | store only confirmed facts, never instructions |
| tool misuse | detect suspicious tool requests | permissions checked in code: recipients, identity, confirmation |
| runaway cost | detect looping prompts | a hard token budget |

In every row, the design approach does not depend on recognising the attack, so disguising the attack does not help.

## Takeaways

- **If the model can read it, assume an attacker can extract it.**
- **Allowlist what may leave; don't blocklist what may not.**
- **Test memory across sessions.** The harm appears later, somewhere else.
- **Prefer controls that don't need to recognise the attack.**
