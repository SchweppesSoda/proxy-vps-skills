---
name: proxy-rule-policy-routing
description: Maintain rule-provider and policy routing in the user's ProxyConfig repository for Egern, Mihomo, Surge, and Loon-style policy groups. Use when adding, removing, reordering, or remapping service rules such as Apple Push, HTTPDNS, AI Suite, streaming media, CN Mainland TV, Speedtest, Telegram, Microsoft, Apple, Google FCM, or custom MyProxy/MyDirect rule sets. Always audit rule targets against policy group definitions before editing.
---

# Maintain Rule Policy Routing

## Core Rule

Treat every rule change as a policy contract change. A rule target must point to an existing policy group, rule ordering must preserve intended precedence, and custom rule providers must stay paired with their rule entries.

This skill does not synchronize Surge split files by itself. If both full and split Surge files are edited, report the intended relationship and leave automated sync to the repository's GitHub Action.

## First Steps

1. Locate ProxyConfig. Prefer the current workspace when it contains `Mihomo/`, `Surge/`, and `Egern/`.
2. Run the rule audit helper before edits:

```powershell
& "<python>" "<skill>/scripts/audit_rule_policy_refs.py" "D:\GitRepo\ProxyConfig" --policy "Apple Push" --policy HTTPDNS
```

3. Read `references/rule-policy-model.md` before changing rule order or adding a new service policy.

## Required Decisions

Ask only for decisions the repo cannot provide:

- Which policy should receive the rule hit if multiple existing groups are plausible.
- Whether the rule belongs before or after a known section such as privacy/adblock, AI, streaming, Apple Push, domestic media, IP rules, or final catch-all.
- Whether to add a new service group or reuse an existing policy.
- Whether a rule-provider URL should be a local/custom provider, MetaCubeX MRS provider, blackmatrix7 list, dler list, or another source.

## Edit Workflow

1. Audit the target policy name and likely aliases.
2. Classify the operation: add rule, remove rule, remap rule to policy, reorder section, or add service policy group plus rule.
3. Update only the matching rule surfaces:
   - Mihomo: `rules` and `rule-providers`.
   - Egern: `rules` and any service `policy_groups` required by the rule target.
   - Surge: `[Rule]` / `Rule.dconf` and service groups if needed.
4. Preserve the established section ordering and nearby comments.
5. Re-run `audit_rule_policy_refs.py`; no rule target should be undefined unless it is a client built-in such as `DIRECT` or `REJECT`.

## Validation

- All rule targets are defined policy groups or known built-ins.
- New rule providers are referenced by at least one rule.
- Removed policy names have no stale rule references unless intentionally retained.
- Rule order matches the requested precedence and does not move catch-all rules earlier.
