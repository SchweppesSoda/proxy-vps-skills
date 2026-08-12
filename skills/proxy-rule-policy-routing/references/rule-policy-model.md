# ProxyConfig Rule Policy Model

## Main Surfaces

- Mihomo Mobile/OpenWrt/Safe: `rules` consume names from `rule-providers`; service groups live under `proxy-groups`.
- Stash: Mihomo-style `rules`, `rule-providers`, and `proxy-groups`, with Stash-specific providers where required.
- Egern: `rules` contain `match` plus `policy`; service groups live under `policy_groups`.
- Surge Full: `[Rule]` lines map rule-set URLs to policies; service groups live in `[Proxy Group]`. Split files are generated from Full.
- Loon Full/Lite: `[Remote Rule]` entries map URLs to policies. Lite may deliberately map dedicated services to `Proxy`.

## Canonical Logical Order

Keep the same family order across clients while preserving client-specific syntax and intentionally omitted services:

1. Narrow private/local/direct rules and explicit custom overrides.
2. Blocking and HTTPDNS handling.
3. AI services.
4. Financial accounts: `PayPal`, `Banking`, `Crypto`.
5. Communications, social, media, and other dedicated service rules.
6. Apple-specific rules, with Apple Push and Apple TV before broad Apple rules.
7. Other platform/tool rules.
8. Broad global/proxy rules.
9. Domestic/geolocation rules.
10. IP and final catch-all rules.

Exact ordering inside families may follow the canonical full configuration, but a narrow service rule must never be moved below a broad rule that can absorb it.

## Finance Precedence Contract

The active rule sequence immediately after the last AI rule must be:

```text
PayPal
Banking
Crypto
```

This is a traffic precedence rule, not merely a policy-group display preference. It applies when the service exists in the client, including Lite profiles that map all three services to `Proxy`. Comments and blank lines are harmless; another active rule between these entries is a violation.

For Loon, numeric tag prefixes are part of maintainability: after moving a block, renumber downstream tags so the displayed sequence matches the actual sequence.

## Common Policy Targets

- Hard-coded: `DIRECT`, `REJECT`.
- Core: `Proxy`, `MyProxy`, `MyDirect`, `Domestic`, `Final`.
- High-priority service: `AI Suite`, `PayPal`, `Banking`, `Crypto`.
- Service: `Telegram`, `YouTube`, `Netflix`, `Apple Push`, `Apple`, `Microsoft`, `HTTPDNS`, `Speedtest`.
- Media pools: `Global TV`, `Asian TV`, `CN Mainland TV`, `Apple TV`.

## Add Or Remap Rules

- Add or update the service policy group first if it does not exist.
- Add the rule-provider definition only when the client needs one.
- Add the rule entry in the matching section.
- Verify the policy name spelling exactly; spaces matter.

## Removal

- Remove both the rule and unused custom provider when the provider is not shared.
- Do not remove a service group just because one rule was removed; it may be used by other rules or manual selection.
