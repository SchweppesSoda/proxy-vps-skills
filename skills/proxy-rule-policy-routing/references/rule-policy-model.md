# ProxyConfig Rule Policy Model

## Main Surfaces

- Mihomo Mobile/OpenWrt/Safe: `rules` consume names from `rule-providers`; service groups live under `proxy-groups`.
- Stash: Mihomo-style `rules`, `rule-providers`, and `proxy-groups`, with Stash-specific providers where required.
- Egern: `rules` contain `match` plus `policy`; service groups live under `policy_groups`.
- Surge Full: `[Rule]` lines map rule-set URLs to policies; service groups live in `[Proxy Group]`. Split files are generated from Full.
- Loon Full/Lite: `[Remote Rule]` entries map URLs to policies. Lite may deliberately map dedicated services to `Proxy`.

## Canonical Full Order

Full configurations must preserve this exact logical order. Multiple providers
belonging to the same named service remain adjacent. Safe/Lite configurations
may omit services, but their remaining services must form a subsequence of this
order.

1. Company intranet, SSID, LAN, private domain/IP, and client hard rules.
2. `MyDirect`, then `MyProxy`.
3. Ad blocking, HTTPDNS handling, then special direct rules.
4. Global AI, then Apple Intelligence.
5. `PayPal`, `Banking`, `Crypto`, active and contiguous.
6. `Telegram`, `Discord`, `Twitter`, `TikTok`.
7. `Emby`, `YouTube`, `Spotify`, `Netflix`, `Disney`.
8. Apple block: Apple Push domains; Apple TV/Music/News; Apple CN; Apple.
9. Regional media block: `Asian TV`, `Global TV`, `CN Mainland TV`.
10. Platform/tool block: Microsoft CN; Microsoft; Scholar Global; Google FCM;
    GitHub; Google Global; Steam CN; GameDownload CN; GameDownload; Steam;
    Speedtest.
11. Broad non-CN/global proxy domains.
12. Narrow domestic services: AI CN; Scholar CN; WeChat/NetEase/Tencent and
    similar reviewed service domains.
13. Broad CN domains and domestic geographic domains.
14. Service IP block: Apple Push; Telegram; Twitter; Google FCM; YouTube;
    Netflix; Google; Proxy.
15. CN IP, ASN, and GEOIP.
16. `FINAL` routed to `Final`.

Apple precedes regional TV so narrow Apple TV rules cannot be absorbed by a
broad global-media list. Within regional TV, Asian TV precedes Global TV and
CN Mainland TV remains the last media family.

Domain rules identify a service more precisely than address ownership, so all
service domains precede service IP rules. Service IP rules remain above broad
CN IP/ASN/GEOIP rules: they supplement IP-literal or already-resolved traffic
without allowing a broad domestic network rule to swallow a known service.
Private/LAN/company IP rules are the deliberate exception at the top because
they protect reachability and local-network safety.

SafeMihomo keeps its existing minimal features. Its catch-all tail is: global
domain, domestic domain, Proxy IP, China IP, Final.

## Finance Precedence Contract

The active rule sequence immediately after the last AI rule must be:

```text
PayPal
Banking
Crypto
```

This is a traffic precedence rule, not merely a policy-group display preference. It applies when the service exists in the client, including Lite profiles that map all three services to `Proxy`. Comments and blank lines are harmless; another active rule between these entries is a violation.

For Loon, numeric tag prefixes are part of maintainability: after moving a block, renumber downstream tags so the displayed sequence matches the actual sequence.

## CN Guard Model

`AICN`, `MicrosoftCN`, `ScholarCN`, `SteamCN`, and `GameDownloadCN` always map
to `Domestic`. `Domestic` defaults to `DIRECT` but remains a selectable group
that can be switched wholesale to `Proxy`. Global counterparts remain separate
and appear earlier than broad global or CN catch-alls.

Do not restore `GoogleCN` or `PayPalCN`. The former was an ineffective attempt
to guard Google before a broad rule; the latter duplicated a service for which
the configured upstream did not provide a valid CN subset. Their old providers,
comments, and references are stale.

## Generated Rule-Set Contract

- Mihomo/Stash consume CustomRules domain and IP MRS artifacts with matching
  `domain` and `ipcidr` behavior.
- Surge/Egern/Loon consume the corresponding LIST artifacts.
- `Mihomo/IP/<Service>.*` and `Surge/IP/<Service>.list` are IP-only; a domain
  provider may never point at those paths.
- Emby has one public automatic set: reviewed manual Emby union V2Fly
  `category-emby`. Clients must not stack a second Emby provider beside it.
- Unused YAML rule providers are errors. Disabled/commented rules and Loon
  plugin declarations are not active rule references.

Banking uses the existing Orz-3 `exchangerate.png` URL in clients that expose a
service icon field: Stash `icon`, Egern `icon`, and Loon Full `img-url`.

## Mihomo Kernel Validation Contract

After changing any Mihomo profile, validate Mobile, OpenWrt, and SafeMihomo
with the pinned Mihomo version and archive checksum declared by CustomRules.
Use an isolated working directory for each profile, seed `GeoSite.dat`, and run
`mihomo -t -f`. A YAML parser only proves syntax; the kernel check additionally
loads Mihomo fields, groups, rules, and the geosite-backed fake-IP filters. It
does not replace rule-order, undefined-policy, provider-type, or URL audits.

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
