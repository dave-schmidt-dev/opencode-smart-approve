# Failure record — OpenCode Smart Approve

Date: 2026-08-29

## Goal

Build an OpenCode equivalent of Codex approve-for-me / Claude automode: broad,
automatic approval of shell permission requests while preserving a strict safety
boundary.

## Outcome

This project is retired as a failed experiment. Model-backed automatic approval
repeatedly passed development but failed held-out release qualification, while
the qualification infrastructure displaced the product.

## Evidence

- 73 commits since 2026-08-08.
- MiMo failed critical safety and usability.
- DeepSeek low failed release usability with 15/200 benign false manuals and 9
  other disagreements.
- DeepSeek high repeated all 15 known benign refusals, added 5 ambiguous false
  approvals, had 1 invalid result, and p95 latency of 16.9 seconds.

## Why it stopped

Broad automatic shell approval and near-zero-risk classification were
incompatible with the tested stochastic reviewers and the strict release gate.
The repository preserves the implementation and qualification record as
historical evidence only.

## Warning

This retired project is non-deployable. Do not install it or use it to
automatically approve shell permissions.
