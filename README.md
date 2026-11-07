# AI Security Testing Lab

[![CI quality gates](https://github.com/K11-Software-Solutions/ai-security-testing-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/K11-Software-Solutions/ai-security-testing-lab/actions/workflows/ci.yml)
[![Code: MIT](https://img.shields.io/badge/Code-MIT-blue.svg)](LICENSE) [![Articles: CC BY 4.0](https://img.shields.io/badge/Articles-CC%20BY%204.0-lightgrey.svg)](articles/LICENSE.md)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![No dependencies](https://img.shields.io/badge/runtime%20deps-none-success)
![No API key needed](https://img.shields.io/badge/API%20key-not%20required-success)

**Measure how safe an LLM application is against attack: prompt injection (direct and indirect), jailbreaks, system-prompt leakage, data exfiltration, excessive agency, memory poisoning and unbounded consumption, with attack success rates and confidence intervals, an adaptive attacker, every defence layer tested on its own, and the cost to legitimate users.**

The ninth lab in a series for quality engineers moving into AI:

| Lab | Question it answers |
|---|---|
| [Becoming an AI Quality Engineer](https://github.com/K11-Software-Solutions/becoming-ai-quality-engineer) | Is the RAG **application** good enough to ship? |
| [LLM Model Testing Lab](https://github.com/K11-Software-Solutions/llm-model-testing-lab) | Is the **model** good enough? |
| [Agent Testing Lab](https://github.com/K11-Software-Solutions/agent-testing-lab) | Is the **agent** safe to let act? |
| [AI Production Monitoring Lab](https://github.com/K11-Software-Solutions/ai-production-monitoring-lab) | Is it **still** good, for the users we actually have, right now? |
| [Multi-Agent Testing Lab](https://github.com/K11-Software-Solutions/multi-agent-testing-lab) | When **agents work together**, does the team do the right thing, and who broke it when it doesn't? |
| [AI Performance and Cost Lab](https://github.com/K11-Software-Solutions/ai-performance-cost-lab) | Is it **fast enough under load**, and what does each **good answer** cost? |
| [AI Evaluation Science Lab](https://github.com/K11-Software-Solutions/ai-evaluation-science-lab) | Can we **trust the evaluator**, and how sure are we? |
| [AI Data Quality Lab](https://github.com/K11-Software-Solutions/ai-data-quality-lab) | Is the **data** behind it all fit to learn from, test with and retrieve? |
| **AI Security Testing Lab** (this repo) | Can an **attacker** make it misbehave, and how sure are we that they can't? |

## How it works

**Orbitly Assist**, a support assistant for a fictional SaaS product, with a secret in its system prompt, retrieval of documents written by outsiders, tools (account lookup, email), memory across sessions and Markdown rendering. Six defence layers can each be switched on or off: input filter (three sensitivities), prompt hardening, tool permissions, memory policy, output filter and token budget, plus the option of keeping the secret out of the prompt.

The model is simulated: whether it follows an injected instruction is random, with a probability set by the attack and the hardening, so attack success is a **rate** to be measured, as with a real model. Everything else is deterministic code. The attack library covers six goals, mapped to the OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS, delivered directly or hidden in retrieved documents, with six mutations that disguise them; an adaptive attacker keeps trying until it succeeds.

## Articles

| # | Article |
|---|---|
| 01 | [Why AI Security Testing Is Different](articles/01-why-ai-security-testing-is-different.md) |
| 02 | [The Target and Its Six Layers](articles/02-the-target-and-its-six-layers.md) |
| 03 | [The Attack Library: Goals, Channels and Mutations](articles/03-the-attack-library.md) |
| 04 | [Defence in Depth: Measure Every Layer](articles/04-defence-in-depth-measure-every-layer.md) |
| 05 | [Adaptive Attackers and What "Zero Successes" Proves](articles/05-adaptive-attackers-and-what-zero-proves.md) |
| 06 | [Guardrails Have a Price](articles/06-guardrails-have-a-price.md) |
| 07 | [Design Fixes Beat Filters: Secrets, Exfiltration and Memory](articles/07-design-fixes-beat-filters.md) |
| 08 | [The Security Gate, Negative Controls and Limitations](articles/08-the-security-gate-ci-limitations.md) |

## Quick start

Requirements: Python 3.11+. No runtime dependencies and no API key.

```bash
git clone https://github.com/K11-Software-Solutions/ai-security-testing-lab.git
cd ai-security-testing-lab
python -m venv .venv
source .venv/bin/activate              # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

```bash
pytest                                                          # 35 tests
python -m evals.run_security_evals                              # the recommended configuration: must pass
SEC_VARIANT=no-hardening python -m evals.run_security_evals     # passes end to end, fails the layer test
python -m experiments.run_experiments                           # the five experiments behind the articles
```

## Repository layout

```text
seclab/
  app.py        Orbitly Assist: the pipeline, six defence layers, the simulated model, outcome checks
  attacks.py    six goals x two channels x six mutations; OWASP and MITRE ATLAS mapping; adaptive attacker; benign set
  measure.py    Wilson intervals, rule of three, campaigns with layer attribution, utility, layer isolation
evals/
  run_security_evals.py   static suite, adaptive attacker, layer-by-layer and utility gates
  thresholds.json         zero-success, layer-reduction and utility thresholds
experiments/    E1 adaptive attacker, E2 defence in depth, E3 what zero proves, E4 filter trade-off, E5 mutations
tests/          35 tests
articles/       the eight articles
.github/workflows/ci.yml   tests -> security gate + 8 weakened configurations that must fail -> experiments reproducibility
```

## What the lab finds

- **An adaptive attacker finds what a static suite only samples.** With the secret in the prompt, a static suite leaked it 9.6% of the time; an attacker who kept trying succeeded in 55% of runs with 10 tries and 90% with 30.
- **"0 of 30 attacks succeeded" is weak evidence:** a system that fails 1% of the time shows zero in 30 attempts three times out of four. Zero in *n* bounds the true rate at about 3/*n*.
- **Defence in depth hides broken layers.** Removing the input filter, hardening or the memory policy changed nothing end to end; only testing each layer on its own revealed them.
- **Some harms have exactly one defence:** tool permissions for tool misuse, the output filter for exfiltration, the budget for runaway cost.
- **Pattern filters stop the attacks in their pattern list.** Split, encoded, translated and paraphrased attacks got past a medium filter 63% to 72% of the time. Raising the filter to high blocked nothing more and refused half of all legitimate requests.
- **Design fixes beat filters.** Output redaction missed every encoded secret; keeping the secret out of the prompt left nothing to leak. An allowlist for links ended exfiltration whatever the attacker's domain.

## CI quality gates

Every push runs three jobs: **tests**; the **security gate** (static suite, adaptive attacker, each layer on its own, cost to legitimate users) plus eight weakened configurations that must each fail for the right reason; and an **experiments** job that fails if the results differ from the committed ones.

## Limitations

A simulated model, a small attack library, a simple adaptive attacker, a pattern-based input filter and one system design. [Article 08](articles/08-the-security-gate-ci-limitations.md#limitations) covers each and how to apply the method to a real system, starting from the K11 [LLM assurance toolkit](https://github.com/K11-Software-Solutions/k11techlab-llm-assurance-toolkit)'s probes.

## About

Created by **Kavita Jadhav**, founder of [K11 Software Solutions](https://github.com/K11-Software-Solutions), Senior SDET and AI Quality Engineer working on LLM evaluation, red teaming and agentic QA systems.

**Licences:** code under the [MIT License](LICENSE); the written material in [`articles/`](articles/LICENSE.md) under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (share and adapt with credit).

Orbitly, its users and its secret are fictional. The attacks are deliberately generic, for testing defences in a simulated system; use them only on systems you are authorised to test.

## Citing

Use GitHub's **Cite this repository** button (from [`CITATION.cff`](CITATION.cff)). Each tagged release is archived on Zenodo with its own DOI; cite the version you used, or the concept DOI for the project as a whole. The DOI badge will appear here after the first release.
