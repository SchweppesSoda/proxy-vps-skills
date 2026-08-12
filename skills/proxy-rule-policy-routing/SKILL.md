---
name: proxy-rule-policy-routing
description: Maintain rule providers, rule order, and policy routing in the user's ProxyConfig repository for Egern, Mihomo, Stash, Surge, and Loon. Use when adding, removing, reordering, or remapping service rules such as AI Suite, PayPal, Banking, Crypto, Apple Push, HTTPDNS, streaming media, Telegram, Microsoft, Apple, Google FCM, Speedtest, MyProxy, or MyDirect. Enforce cross-client precedence contracts and audit every rule target before and after editing.
---

# Maintain Rule Policy Routing

## Core Rule

Treat every rule change as a cross-client policy contract change. A rule target must point to an existing policy group, rule ordering must preserve intended precedence, and custom rule providers must stay paired with their rule entries.

The finance precedence contract is fixed unless the user explicitly overrides it:

```text
AI rules → PayPal → Banking → Crypto → other service rules
```

`PayPal`, `Banking`, and `Crypto` must be active, contiguous, and in that exact order immediately after the last AI rule. Comments and blank lines may separate sections; unrelated active rules may not split the sequence.

Do not edit Surge split files directly. Edit `Surge/AutoSurge.conf`, report local split drift, and leave synchronization to the repository's GitHub Action.

## First Steps

1. Locate ProxyConfig. Prefer the current workspace when it contains `Mihomo/`, `Surge/`, and `Egern/`.
2. Read `references/rule-policy-model.md` before changing rule order or adding a service.
3. Run the full rule audit before edits. Run a filtered audit only as an additional focused view:

```powershell
& "<python>" "<skill>/scripts/audit_rule_policy_refs.py" "D:\GitRepo\ProxyConfig"
& "<python>" "<skill>/scripts/audit_rule_policy_refs.py" "D:\GitRepo\ProxyConfig" --policy PayPal --policy Banking --policy Crypto
```

4. Search definitions and references across `Mihomo/`, `Stash/`, `Surge/`, `Loon/`, and `Egern/` before editing.

## Required Decisions

Ask only for decisions the repository and the canonical model cannot provide:

- Which policy should receive the rule hit if multiple existing groups are plausible.
- Whether a genuinely new rule family belongs before or after an existing canonical section.
- Whether to add a new service group or reuse an existing policy.
- Whether a rule-provider URL should be a local/custom provider, MetaCubeX MRS provider, blackmatrix7 list, dler list, or another source.

## Edit Workflow

1. Audit the target policy name and likely aliases.
2. Classify the operation: add rule, remove rule, remap rule to policy, reorder section, or add service policy group plus rule.
3. Compare every active client surface before choosing the edit set:
   - Mihomo: Mobile, OpenWrt, and Safe profiles; update `rules`, `rule-providers`, and service groups when applicable.
   - Stash: `rules`, `rule-providers`, and service groups.
   - Egern: `rules` and any service `policy_groups` required by the rule target.
   - Surge: canonical `[Rule]` lines in `AutoSurge.conf` and service groups if needed; do not hand-edit generated split files.
   - Loon: Full and Lite remote rules plus service groups when applicable.
4. Preserve intentionally minimal clients. Do not add a missing service to Safe or Lite solely for symmetry; when a client already consumes the service, enforce the same logical ordering even if it maps to a simplified policy such as `Proxy`.
5. Preserve nearby comments. If Loon uses numbered tags, renumber them to match physical rule order after moving entries.
6. Re-run the full audit. Treat undefined policy targets and finance-order violations as failures.

## Validation

- All rule targets are defined policy groups or known built-ins.
- New rule providers are referenced by at least one rule.
- Removed policy names have no stale rule references unless intentionally retained.
- Every applicable full configuration contains the contiguous sequence `AI → PayPal → Banking → Crypto`.
- Loon numbered tags remain sequential after reordering.
- Broad global, domestic, IP, and final catch-all rules remain below specific service rules.
- Surge Split is reported as generated drift until its Action has synchronized it.
