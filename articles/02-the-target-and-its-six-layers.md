# 02. The Target and Its Six Layers

> **Series:** AI Security Testing Lab · [Index](../README.md#articles) · Previous: [01](01-why-ai-security-testing-is-different.md) · Next: [03. The Attack Library](03-the-attack-library.md)

## Orbitly Assist

The system under test ([`seclab/app.py`](../seclab/app.py)) is a support assistant for a fictional SaaS product, with the features that make real assistants attackable:

| Feature | Why it matters to an attacker |
|---|---|
| A system prompt holding an internal escalation code | something to steal |
| Retrieval of documents and tickets, some written by outsiders | a channel for **indirect** injection |
| Tools: account lookup and email | a way to make it **act** |
| Memory that persists across sessions | a way to make an attack **last** |
| Answers rendered as Markdown, including links and images | a way to send data **out** |
| Pay-per-token generation | a way to cost the owner money |

## The six defence layers

```text
request ──► input filter ──► model (+ hardening) ──► tool permissions / memory policy ──► output filter ──► user
                                                       └── token budget
```

| Layer | What it does | Kind |
|---|---|---|
| **Input filter** | refuses requests matching known attack patterns; sensitivity low, medium or high | pattern matching |
| **Hardening** | an instruction hierarchy and delimiters marking retrieved text as data ("spotlighting") | lowers the model's compliance |
| **Tool permissions** | email only to the user's own address; identity bound to the session | deterministic |
| **Memory policy** | stores only facts the user confirmed, never instructions | deterministic |
| **Output filter** | redacts the secret, removes links to domains not on an allowlist and all images, blocks disallowed content | deterministic |
| **Budget** | caps tokens per request | deterministic |

A seventh option is a design decision rather than a filter: **keep the secret out of the system prompt** and in a backend the model cannot read.

Only two layers act on the model's *willingness*: the input filter (by refusing to pass the text on) and hardening (by making the model less likely to comply). The rest act on what the model *does*, after it has been fooled. That distinction turns out to matter a great deal (article 04).

## Three configurations

| Configuration | Meaning |
|---|---|
| `Defences.none()` | everything off: the baseline |
| `Defences()` | every layer on, input filter at medium, secret in the prompt |
| `Defences.recommended()` | every layer on, input filter at **low**, secret **out** of the prompt: what the experiments support |

Why "recommended" lowers the input filter and moves the secret is the subject of articles 06 and 07.

## The pipeline as a test harness

`handle(request, session, defences, rng)` runs one request through every layer and records **which layer stopped it**. `succeeded(...)` then checks whether the attacker's goal was reached in what the user actually received, or in the world: an email sent, a memory written, tokens spent. As in every lab in this series, the check is on outcomes, not on what the model said it would do.
