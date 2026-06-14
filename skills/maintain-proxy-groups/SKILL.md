---
name: maintain-proxy-groups
description: Maintain proxy and policy groups plus provider source metadata in the user's ProxyConfig repository for MIHOMO/Mihomo, Surge, and Egern. Use when adding, deleting, renaming, splitting, or re-sourcing airport providers, self-hosted VPS groups, relay/dialer groups, region groups, MassData/Others pools, service policy groups, provider URLs, provider paths, Sub-Store collection names, node prefixes, or external-policy-name-prefix values. Especially for requests involving examples like TAG airports, PO0 SG, OIX/OixCloud removal, DMIT PRO removal, Core JP/Edge JP split, or provider source/prefix/path changes. Always audit group definitions and references before editing and ask for behavior choices such as select, fallback, url-test/auto_test, or smart when not specified.
---

# Maintain Proxy Groups

## Core Rule

Treat every group or provider-source change as a reference-graph change. Before editing, identify the group's definitions, provider source entries, direct consumers, aggregate consumers, service consumers, rules, DNS exceptions, comments, and generated/split counterparts across Mihomo, Surge, and Egern.

If the user says the task is hypothetical, inspect and explain only; do not modify ProxyConfig.

## First Steps

1. Locate the ProxyConfig repo. Prefer the current workspace when it contains `Mihomo/`, `Surge/`, and `Egern/`.
2. Read files as UTF-8 and preserve emoji, Chinese text, group spelling, hyphen/underscore style, and existing ordering.
3. Run the audit helper before edits:

```powershell
& "<python>" "<skill>/scripts/audit_proxy_refs.py" "D:\GitRepo\ProxyConfig" --target "OIX" --target "DMIT PRO" --target "CORE JP"
```

Use the bundled `scripts/audit_proxy_refs.py`; it has no third-party dependencies. Also use `rg` for confirmation when a change is risky or the target has ambiguous aliases.

Read `references/proxyconfig-group-model.md` when you need the current repository's group taxonomy, hot spots, or operation checklist.

## Required Questions

Ask only for decisions that cannot be inferred safely. For an airport add like `TAG`, ask:

- Subscription/provider source for each client: Mihomo provider URL/path, Surge `policy-path`, Egern `urls`.
- Display name and prefix: provider id, external node prefix, visible per-region group prefix, flags.
- Regions to create: HK, TW, SG, JP, US, or another set.
- Per-region behavior: `select`, `url-test`/Egern `auto_test`, `fallback`, `smart`, or mixed by region/client.
- Inclusion policy: region aggregators, `AllAirports`/`Speedtest`, `MassData`, `Others`, service groups, DNS exceptions.

For a self-hosted add like `PO0 SG`, ask:

- Source provider/list and whether it is one region, a pooled provider, or a filtered subset of an existing provider.
- Visible group name, flag, provider key, icon/prefix, and whether it should be flattened.
- Whether to include it in `Proxy`/`AllRegions`, mass lists, Relay/Dialer candidates, `Emby`, `Speedtest`, `AI Suite`, or only manual groups.

For provider source maintenance, ask:

- Whether this is a source-only update or whether visible groups should also be renamed.
- Client-specific source strings: Mihomo `url`/`path`, Surge `policy-path`, Egern `urls`.
- Prefix policy: preserve the existing node prefix, change it, remove it, or keep client-specific prefixes.
- Whether stale source names such as old Sub-Store collection names, gist raw names, cache paths, and comments should be removed.

For deletion or splitting, ask how to handle consumers:

- Remove from consumers, replace with a new group, or keep an alias temporarily.
- Remove provider source too, or only remove visible groups.
- For split operations, whether the split uses separate provider URLs, filters over one provider, or manual membership.

## Edit Workflow

1. Build an audit report for all raw names and aliases. Include normalized forms: spaces, hyphens, underscores, provider suffixes, and emoji-stripped names.
2. Classify the target as airport provider, self-hosted provider, relay/dialer, region aggregate, service group, rule target, DNS/plugin name, or provider source metadata.
3. For source-only updates, separate provider source metadata from visible policy/group names; do not rename visible groups unless requested.
4. Draft the exact edit set per client. Do not assume Mihomo, Surge, and Egern have identical provider inventories or source naming.
5. Apply minimal edits in the established section order. Keep repeated service lists in sync where the repo intentionally does not use anchors.
6. Re-run `audit_proxy_refs.py` for old and new names, including old source aliases and cache path fragments.
7. Report unresolved references, intentional leftovers, and any client skipped because it lacks the corresponding structure.

## Validation

Use all applicable checks:

- `audit_proxy_refs.py` shows no dangling old references after deletion and shows the expected new references after addition/split.
- `rg` confirms no missed spelling variants.
- YAML-ish files retain indentation and valid list/map structure.
- Surge split files and `Surge/AutoSurge.conf` stay consistent if both are maintained.
- Do not finish with encoding-damaged output. If PowerShell displays mojibake, re-read with Python using UTF-8 before trusting what you saw.

