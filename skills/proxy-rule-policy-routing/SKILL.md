---
name: proxy-rule-policy-routing
description: Maintain ProxyConfig rule providers, precedence and rule-to-policy mappings. Group definitions and DNS resolver settings use their own skills.
---

# Proxy rule policy routing

Start with the changed rule/provider/target and neighboring precedence blocks. A target must resolve, provider format must match the client, and domain/IP precedence must remain valid.

## Route

- Adding, removing, reordering or remapping rules: read the relevant sections of [rule policy model](references/rule-policy-model.md) for ordering, source format and profile exceptions.
- Creating/deleting/renaming a group also uses `proxy-groups`; remapping to an existing group stays here.
- Changing a generated scope or source→artifact publication uses `proxy-generated-config-sync`. An existing published URL does not by itself require a publication workflow.

## Work and finish

Preserve applicable canonical order, including AI → PayPal → Banking → Crypto. Safe/Lite may remain subsequences. Find direct consumers before deleting providers or targets; broaden name searches across clients for shared identity changes. Ordinary rule migration does not disable independent HTTPDNS/ad-block/reporting modules or change saved user selections.

Edit canonical inputs and complete the affected reference/order checks. `scripts/audit_rule_policy_refs.py <repo> --policy <name>` gives a focused view; it still includes shared checks and is not a promise of isolated validation. Use an unfiltered audit for broad ordering changes or requested full review. Validate only changed Mihomo profiles and affected derivatives with the pinned kernel; see the model reference for `--config`. Do not require a full audit before and after every edit. Report local checks and any pending generator/build/publication separately; do not claim unpublished sources are live.

The audit reports `checked`, `skipped`, and `missing` profile inventories. Missing required canonical profiles (including independent Egern Lite) mean incomplete coverage and exit code 2; they are never a pass. `checked` only means this script's documented checks ran, not client/runtime validation. Generated derivatives and retired Loon Lite are not canonical parity targets. Do not install source skill changes unless the current task authorizes installation.
