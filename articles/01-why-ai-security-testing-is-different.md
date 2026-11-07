# 01. Why AI Security Testing Is Different

> **Series:** AI Security Testing Lab · [Index](../README.md#articles) · Next: [02. The Target and Its Six Layers](02-the-target-and-its-six-layers.md)

This is the ninth lab in a series for quality engineers moving into AI. Earlier labs touched security in passing: a planted prompt injection in the [Agent Testing Lab](https://github.com/K11-Software-Solutions/agent-testing-lab), relayed injection in the [Multi-Agent Testing Lab](https://github.com/K11-Software-Solutions/multi-agent-testing-lab), harmful-request probes in the [LLM Model Testing Lab](https://github.com/K11-Software-Solutions/llm-model-testing-lab). This lab makes security the subject, and asks the question a security review actually needs answered: **how sure are we that an attacker can't make it misbehave?**

## Three differences from traditional security testing

**1. The vulnerability is the feature.** A SQL injection exists because code mixed data and commands by mistake. Prompt injection exists because a language model is *designed* to follow instructions in text, and cannot reliably tell the user's instructions from instructions hidden in a document it was asked to read. There is no patch that removes it. Defences reduce the rate; they do not reach zero.

**2. Results are rates, not verdicts.** The same attack against the same system can succeed on one try and fail on the next. A security test of an LLM application is therefore a **measurement**: an attack success rate, with a confidence interval, against a defined set of attacks and a defined attacker. "We ran the red-team suite and nothing got through" is a statement about a sample, and article 05 shows how little a small sample proves.

**3. Attackers adapt.** A fixed list of attack prompts tests yesterday's attacker. A real one rephrases, encodes, translates and tries again. The lab's adaptive attacker turned a 0% success rate on the first try into 55% within ten tries against the same system.

## What this lab measures

| Question | Article |
|---|---|
| What are we defending, and with which layers? | 02 |
| What do the attacks look like, and how do they map to OWASP and MITRE ATLAS? | 03 |
| Which layer is actually doing the work, and which could fail unnoticed? | 04 |
| What does an adaptive attacker achieve, and what does "0 successes" prove? | 05 |
| What do guardrails cost legitimate users? | 06 |
| Which problems should be designed away instead of filtered? | 07 |
| What should a security gate in CI check? | 08 |

## Why simulate the model

The assistant's model is simulated: whether it follows an injected instruction is random, with a probability set by the attack's strength and the prompt's hardening. Everything else (filters, permissions, budgets, the output renderer) is ordinary deterministic code, as it would be in a real system. This makes every experiment repeatable and fast (the full gate runs in about a second), and it lets the lab show what each **method** can and cannot establish. The success rates are not predictions for any real model; the methods (campaigns, adaptive attackers, layer isolation, upper bounds, utility cost) carry over directly. Article 08 explains how to point them at a real system.
