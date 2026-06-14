# ProxyConfig Rule Policy Model

## Main Surfaces

- Mihomo: `rules` consume names from `rule-providers`; service groups live under `proxy-groups`.
- Egern: `rules` contain `match` plus `policy`; service groups live under `policy_groups`.
- Surge: `Rule.dconf` and `[Rule]` lines map rule-set URLs to policy names; service groups live in `ProxyGroup.dconf` or `[Proxy Group]`.

## Ordering Invariants

- Private/direct and adblock/HTTPDNS rules stay near the top.
- Custom `MyProxy`/`MyDirect` overrides stay before broad service rules.
- AI and streaming rules stay before broad global/geolocation rules.
- Apple Push is intentionally separated and should not be buried below broad Apple or domestic-media rules.
- IP rules and final catch-all rules stay late.

## Common Policy Targets

- Hard-coded: `DIRECT`, `REJECT`.
- Core: `Proxy`, `MyProxy`, `MyDirect`, `Domestic`, `Final`.
- Service: `AI Suite`, `Telegram`, `YouTube`, `Netflix`, `Apple Push`, `Apple`, `Microsoft`, `HTTPDNS`, `Speedtest`.
- Media pools: `Global TV`, `Asian TV`, `CN Mainland TV`, `Apple TV`.

## Add Or Remap Rules

- Add or update the service policy group first if it does not exist.
- Add the rule-provider definition only when the client needs one.
- Add the rule entry in the matching section.
- Verify the policy name spelling exactly; spaces matter.

## Removal

- Remove both the rule and unused custom provider when the provider is not shared.
- Do not remove a service group just because one rule was removed; it may be used by other rules or manual selection.
