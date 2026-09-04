---
name: proxy-generated-config-sync
description: Coordinate generated configuration writers in the user's ProxyConfig and CustomRules repositories. Use only when a task involves generated writer ownership, marker/field/whole-file scopes, Airport DNS, Provider Compatibility, OpenWrt-to-WAN2 generation, Surge full-to-split publication, CustomRules cross-repository publication, shared locks, or transactional writes. Do not use for ordinary group, DNS, or rule edits that stay inside manual/canonical scopes.
---

# Coordinate Generated Configuration Writers

This skill is the handoff and safety layer for generated configuration. It does
not contain provider inventories or reimplement repository algorithms. It
locates the repository-owned CLI, generator, workflow, and tests, then makes
their ownership and publication boundaries explicit.

## When to load it

Load this skill when a change will do any of the following:

- add, remove, or change an automatically generated marker or selected field;
- change a whole-file derivative such as OpenWrt WAN2 or Surge split output;
- change Airport DNS or Provider Compatibility automation;
- publish or consume a CustomRules cross-repository artifact;
- change a writer's concurrency group, transaction, diff allowlist, or
  canonical/generated contract.

An ordinary DNS, group, or rule edit does not need this skill merely because a
client also has generated files. In that case use the domain skill and hand off
only if the edit crosses one of the boundaries above.

## Repository discovery

Resolve these at runtime from the current checkout; never assume a Windows
drive, an installation directory, or a copied example path:

- `<proxyconfig-root>` contains `Mihomo/`, `Surge/`, `Stash/`, `Loon/`, and
  `Egern/`.
- `<proxy-vps-skills-root>` contains `skills/` and this skill.

Read `Sub-Store/AGENTS.md` and
`<proxyconfig-root>/Sub-Store/config/generated-writers.json` first. Then read
the automation reference that matches the selected writer and inspect the
actual workflow before making a decision. The index is a thin ownership map;
the repository CLI, tests, and automation reference remain authoritative for
implementation details.

## Operating contract

1. Inventory the canonical inputs, target files, current markers/fields, and
   the existing diff before editing.
2. Identify every affected pipeline: Airport DNS, Provider Compatibility,
   OpenWrt WAN2, Surge full-to-split, and/or CustomRules auto-build. Validate
   each affected pipeline separately and preserve each writer's own scope; do
   not combine pipelines into a new shared owner. A domain skill may be loaded
   alongside this one for semantic decisions.
3. Treat `whole-file`, `marker-pair`, and `field-selector` as different
   ownership scopes. A writer may replace only its declared scope.
4. A physical file may have multiple writers only when their scopes do not
   overlap and every writer uses the same declared concurrency group. The
   current shared Stash and Loon writers use
   `generated-file-writers-main`.
5. Run the repository-owned CLI in dry-run/check mode, stage all required
   outputs, and run validators before installing any output. A required
   fetch, parse, marker, or validation failure is zero-write.
   Contract `validators` are non-executable locators: resolve the documented
   command from the workflow/reference and never pass a raw index string to a
   shell. Publishers and write-capable generators are not read-only validators.
6. Enforce the writer's diff allowlist. A generated file is not an invitation
   to edit the surrounding manual/canonical text.
7. Keep capability URLs, bearer tokens, provider credentials, and derived
   secret-bearing URLs out of logs, JSON, reports, and error messages. Use the
   writer's masking and validation behavior rather than printing raw values.
8. For cross-repository publication, follow
   [references/cross-repo-publication.md](references/cross-repo-publication.md)
   and report any partial state; do not assume that two repositories can be
   rolled back atomically.

## Current pipelines

| Pipeline | Canonical inputs | Generated ownership |
| --- | --- | --- |
| Airport DNS | `Sub-Store/config/airport-domain-sources.json` and the reviewed Mihomo Mobile profile | Airport DNS marker blocks in Stash/Loon and marked AirportServers sources in CustomRules |
| Provider Compatibility | provider registry/provider JSON plus canonical profile(s) | Provider-compat marker blocks in Mihomo Mobile/OpenWrt, Stash, Egern, and Loon; WAN2 is delegated to its generator |
| OpenWrt WAN2 | `Mihomo/AutoMihomo.OpenWrt.yaml` plus the WAN1-primary provider list | `Mihomo/AutoMihomo.OpenWrt-WAN2.yaml` as a whole-file derivative |
| Surge full-to-split | `Surge/AutoSurge.conf` | `Surge/Split Conf/AutoSurge/` outputs; the full profile remains canonical |
| CustomRules auto-build | reviewed `master` sources and pinned toolchain | `auto-build` rule artifacts, metadata, and reports consumed by clients |

Read [references/generated-writer-contract.md](references/generated-writer-contract.md)
when a marker, field, whole-file derivative, or ownership question is involved.

## Handoff and completion

Return to `proxy-groups`, `proxy-dns-routing`, or
`proxy-rule-policy-routing` for provider/group, DNS semantics, or rule-order
decisions. Keep this skill loaded for the generated handoff and final checks.

Before reporting completion, confirm the relevant CLI/checks passed, no-op
outputs did not change bytes or mtime, only declared scopes changed, and the
global consistency audit has an explicit scanned/skipped/generated report.
