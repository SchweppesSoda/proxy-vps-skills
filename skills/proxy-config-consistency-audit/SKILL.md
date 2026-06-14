---
name: proxy-config-consistency-audit
description: Audit the user's ProxyConfig repository for cross-client consistency without editing files. Use when checking whether Egern, Mihomo, and Surge have mismatched provider inventories, missing airport region groups, stale references after deletions, undefined rule policy targets, missing Others/MassData/Speedtest coverage, or general drift after proxy, DNS, or rule changes. This skill is read-only and should be used before or after risky ProxyConfig edits.
---

# Audit Proxy Config Consistency

## Core Rule

This is a read-only audit skill. Do not edit ProxyConfig while using it unless the user separately asks for a fix and a more specific maintenance skill applies.

The goal is to identify inconsistency clearly enough that a follow-up edit can be scoped safely.

## First Steps

1. Locate ProxyConfig. Prefer the current workspace when it contains `Mihomo/`, `Surge/`, and `Egern/`.
2. Run the bundled audit:

```powershell
& "<python>" "<skill>/scripts/audit_proxy_consistency.py" "D:\GitRepo\ProxyConfig"
```

3. For a focused provider or group, add filters:

```powershell
& "<python>" "<skill>/scripts/audit_proxy_consistency.py" "D:\GitRepo\ProxyConfig" --target LiangXin --target OixCloud
```

Read `references/consistency-checks.md` when interpreting multi-client differences.

## Audit Workflow

1. Report provider inventory by client.
2. Report region child group coverage for HK/TW/SG/JP/US.
3. Report likely provider or region bases that exist in only some clients.
4. Report undefined rule policy targets when they are visible to the auditor.
5. Use `rg` for aliases when a finding involves renamed providers, emoji-bearing groups, or hyphen/underscore variants.

## Validation

- Findings include file and line numbers when possible.
- Intentional asymmetry is called out separately from likely drift.
- No repo files are modified by the audit.
