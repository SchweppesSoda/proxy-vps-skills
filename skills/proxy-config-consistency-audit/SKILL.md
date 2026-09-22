---
name: proxy-config-consistency-audit
description: Inspect ProxyConfig cross-client consistency or unexplained generated drift without changing configs. Use for requested audits or evidence spanning multiple domains.
---

# Proxy consistency audit

This workflow inspects and reports; it does not authorize repair. If the user already requests audit and repair, finish diagnosis then use the relevant maintenance workflow without asking again.

## Choose scope

- One provider, domain or policy: prefer the corresponding focused domain audit or exact reference search.
- Requested global review or unexplained cross-domain drift: run `scripts/audit_proxy_consistency.py <repo>`.
- Classification, expected asymmetry and follow-up: read [consistency checks](references/consistency-checks.md).
- Writer evidence: inspect only affected entries of `Sub-Store/config/generated-writers.json` and their documented read-only checks.

The global script covers inventory, visible targets and writer structure. It does not run all deeper audits or generators. `--target <name>` focuses the report; shared checks can still run. Add a domain audit only to resolve a concrete finding or meet the requested coverage.

## Completion

Report actionable findings with file/line evidence, scope checked, intentional asymmetry, skipped checks and downstream build status. Do not turn a missing client feature into mandatory parity. Run only documented side-effect-free checks; never execute index validator strings, network fetches, generators or publishers as part of this read-only audit. Distinguish tool/environment failures from configuration defects and mask credentials/capability values. Stop when the requested coverage is assessed; do not repeat successful checks or silently expand into repairs.

The audit reports `checked`, `skipped`, and `missing` profile inventories. Missing required canonical profiles (including independent Egern Lite) mean incomplete coverage and exit code 2; they are never a pass. `checked` only means this script's documented checks ran, not client/runtime validation. Generated derivatives and retired Loon Lite are not canonical parity targets. Do not install source skill changes unless the current task authorizes installation.
