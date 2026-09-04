---
name: proxy-config-consistency-audit
description: Run a read-only global consistency audit for the user's Mihomo, Surge, Stash, Loon, Egern, and CustomRules-linked ProxyConfig surfaces. Use before or after risky provider, DNS, rule, or generated-writer changes to detect inventory drift, stale references, undefined policy targets, marker/field ownership conflicts, generated drift, and missing validators. Never edit files with this skill.
---

# Audit Proxy Config Consistency

This is the read-only orchestration entrypoint. It identifies inconsistency so
that a follow-up can be scoped to `proxy-groups`, `proxy-dns-routing`,
`proxy-rule-policy-routing`, or `proxy-generated-config-sync`. Do not modify
ProxyConfig while using this skill unless the user separately requests a fix
and the appropriate maintenance skill is loaded.

## First steps

1. Resolve `<proxyconfig-root>` from the current checkout and discover the
   maintained profiles under `Mihomo/`, plus Surge Full, Stash, Loon, and
   Egern. Do not assume a generic legacy profile exists.
2. Read `Sub-Store/config/generated-writers.json` and, when generated files
   are involved, the matching Sub-Store automation references and workflows.
3. Run the bundled audit from `<proxy-vps-skills-root>`:

```powershell
& "<python>" "<proxy-vps-skills-root>/skills/proxy-config-consistency-audit/scripts/audit_proxy_consistency.py" "<proxyconfig-root>"
```

Use `--target` only as an additional focused view. Use `rg` for aliases and
exact consumers, but redact capability URLs, tokens, and credentials.

## Global audit workflow

Report the following separately, with file/line evidence where available:

1. Provider/source inventory and region child-group coverage across all five
   clients. Distinguish source, collection, published artifact, and consumer;
   matching display names do not prove identity.
2. Policy/rule references, including undefined targets, orphan providers,
   service-order violations, and CustomRules artifact branch/path drift.
3. DNS projections and stale AirportServers references, keeping Airport DNS
   inventory separate from Provider Compatibility host/fake-IP data.
4. Generated-writer contract checks: every index writer has resolvable inputs,
   entrypoint/workflow, targets, validators, and exclusions; every marker pair
   or selected field appears once in its declared owner scope; shared physical
   files use one lock and non-overlapping selectors; whole-file derivatives
   point back to their canonical input.
5. Workflow diff allowlists, canonical-versus-generated drift, Surge full/split
   state, OpenWrt baseline/WAN2 state, and CustomRules `master`/`auto-build`
   publication state.

The bundled global script covers file discovery, provider/region inventory,
visible undefined targets, and generated-contract structure, markers, locks,
targets, and delegation. It does not silently run the deeper domain audits or
any repository writer. Invoke the focused read-only audits when their domain
is in scope:

```powershell
& "<python>" "<proxy-vps-skills-root>/skills/proxy-groups/scripts/audit_proxy_refs.py" "<proxyconfig-root>" --target "<name>"
& "<python>" "<proxy-vps-skills-root>/skills/proxy-dns-routing/scripts/audit_dns_routing.py" "<proxyconfig-root>" --airportservers
& "<python>" "<proxy-vps-skills-root>/skills/proxy-rule-policy-routing/scripts/audit_rule_policy_refs.py" "<proxyconfig-root>"
```

When a generated writer is implicated, treat its `validators` entries as
discovery hints, never as shell commands. Run a repository-owned command only
when its workflow or automation reference explicitly documents a
side-effect-free test/check mode. Otherwise report it as skipped; this
read-only skill never invokes generators, publishers, network fetches, or
write-capable validation. A writer check does not replace a domain semantic
audit.

## Findings and intentional asymmetry

Classify findings as:

- likely drift or a release blocker;
- intentional client asymmetry, with the reason and owner;
- generated output waiting for its workflow;
- external CustomRules publication/build still pending;
- environment/toolchain failure rather than configuration failure.

Always state what was scanned, what was skipped, and which outputs were
generated or only checked. For each delegated audit, state `checked`,
`skipped`, or `waiting for downstream build`. Do not treat an absent client
feature as an error without confirming that the repository contract expects
parity.

## Validation

- Run the bundled consistency audit and all applicable focused audits.
- Re-check old/new aliases after rename or deletion across all five clients.
- Confirm generated marker/field scopes do not overlap and shared writers use
  the same concurrency group.
- Confirm Surge Full is canonical and split output is workflow-generated.
- Confirm CustomRules consumers refer to the intended `auto-build` artifacts,
  while reviewed sources remain on `master`.
- Keep output secret-safe: never print complete provider capability URLs,
  bearer tokens, or node credentials.
