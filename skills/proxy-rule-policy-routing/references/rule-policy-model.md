# ProxyConfig Rule Policy Model

## CustomRules source, artifact, and consumer chain

CustomRules has two deliberate branches with different ownership:

```text
master reviewed sources/catalogs/toolchain
        → Auto Build Rules
auto-build generated YAML/MRS/LIST + manifest/checksums
        → client rule-provider consumers
```

Edit reviewed sources on `master`; never hand-edit files on `auto-build`.
For source or builder changes, choose tests covering the changed behavior.
Before publication or switching consumers, complete the applicable deterministic
build and artifact verification gates; a local edit is not a live artifact. The branch and artifact path in each canonical client configuration
are part of the contract.

If a source change also touches a generated marker, selected field, whole-file
derivative, diff allowlist, lock, or cross-repository publication, load
`proxy-generated-config-sync`. That skill owns writer scope and publication
hygiene; this reference remains authoritative for rule semantics and order.

## Main Surfaces

- Mihomo Mobile/OpenWrt/Safe: `rules` consume names from `rule-providers`; service groups live under `proxy-groups`.
- Stash: Mihomo-style `rules`, `rule-providers`, and `proxy-groups`, with Stash-specific providers where required.
- Egern Full/Lite: independent canonical profiles; `rules` contain `match` plus `policy`, and service groups live under `policy_groups`. Lite may deliberately map dedicated services to `Proxy`.
- Loon Full/Lite are retired and excluded from active audits even when files remain. Historical parsers and tests retain `[Remote Rule]` support for explicit archive work.

## Canonical Full Order

Full configurations must preserve this exact logical order. Multiple providers
belonging to the same named service remain adjacent. Safe/Lite configurations
may omit services, but their remaining services must form a subsequence of this
order.

1. Company intranet, SSID, LAN, private domain/IP, and client hard rules.
2. `MyDirect`, then `MyProxy`.
3. Ad blocking, HTTPDNS handling, then special direct rules.
4. Global AI non-address rules, then Apple Intelligence.
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
14. Service address block, including Claude IP. Preserve the established
    subsequence: Claude; Apple Push; Telegram; Twitter; Google FCM; YouTube;
    Netflix; Google. Additional service CIDR/ASN partitions stay in this block;
    their insertion is decided by reviewed overlap evidence and client regression
    checks, without inventing a new universal service sequence.
15. Broad proxy address rules, including `Address/Classical/Proxy`.
16. Broad CN IP, ASN, and GEOIP, including `Address/Classical/China`.
17. Exactly one final catch-all, last, routed to `Final`.

Apple precedes regional TV so narrow Apple TV rules cannot be absorbed by a
broad global-media list. Within regional TV, Asian TV precedes Global TV and
CN Mainland TV remains the last media family.

The non-address segment includes DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD,
DOMAIN-WILDCARD, USER-AGENT, PROCESS-NAME and URL-REGEX. Preserve their literal
rules, relative order and targets in the owning business block; classical syntax
does not make them address rules. All such business rules, even an unfamiliar
service name or inline GEOSITE/domain rule, precede service addresses. IP-CIDR,
IP-CIDR6 and IP-ASN belong to the address segment; ASN must not be represented as
an ipcidr MRS. WeChat ASN is a service address, while broad China ASN is a CN tail.

Address rules supplement IP-literal or already-resolved traffic. Service
addresses remain above broad Proxy and CN address rules so those tails cannot
swallow a known service. The early address exceptions are precise: maintained
private/LAN/company rules; full-profile `Classical/Special` with only its existing
`100.64.0.0/10` address member; and the two restored Stash HTTPDNS providers below.
An arbitrary DIRECT CIDR, a name containing Private/Special, or another classical
provider is not an exception. Private set members must remain local/reserved
CIDRs, not public networks or ASNs. SafeMihomo's reviewed company `9.0.0.0/8`
remains a client hard rule. Local AND conditions may use supported NETWORK,
DST-PORT/SRC-PORT and target CIDR leaves only: at least one local/reserved target
CIDR is required, every address condition must be local, and unknown, nested
OR/NOT or public-address conditions never receive this exception.

`Stash-HTTPDNS-Block` and `Stash-HTTPDNS-Loon-Extra` may retain their public CIDRs
in the early HTTPDNS block only with policy `HTTPDNS` and their exact maintained
source URLs. This is a restored HTTPDNS handling contract, not a general exemption
for HTTPDNS-named providers. Actual snapshot contents still require validation;
an unknown source or unsupported syntax cannot pass.

SafeMihomo keeps its existing minimal features. Its tail is: global non-address,
domestic non-address, any already-enabled service addresses, Proxy IP, China IP,
Final. Applying this order does not add missing services to Safe or Lite.

## Finance Precedence Contract

The active rule sequence immediately after the last AI non-address rule,
including Apple Intelligence when present, must be:

```text
PayPal
Banking
Crypto
```

This is a traffic precedence rule, not merely a policy-group display preference. It applies when the service exists in the client, including Lite profiles that map all three services to `Proxy`. Comments and blank lines are harmless; another active rule between these entries is a violation. Claude IP or another address rule targeting `AI Suite` belongs to the later address block and never resets the finance boundary.

For explicitly requested historical Loon edits, numeric tag prefixes preserve the displayed sequence after moving a block.

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
- Egern consumes the corresponding LIST artifacts; historical Loon parsing supports the same format. Mixed business sources use `Surge/NonIP/<original-source>.list` and `Surge/Address/<original-source>.list`, preserving the original `Classical/` or `Policy/Classical/` path. The non-address side stays at the original business position and target; the address side follows the segment contract above.
- `Mihomo/IP/<Service>.*` and `Surge/IP/<Service>.list` are IP-only; a domain
  provider may never point at those paths.
- Address partitions stay classical and preserve CIDR/ASN members. A NonIP
  partition may additionally have a domain MRS only when its actual members are
  exclusively DOMAIN/DOMAIN-SUFFIX. Directory names and manifest behavior do not
  substitute for content validation.
- Emby has one public automatic set: reviewed manual Emby union V2Fly
  `category-emby`. Clients must not stack a second Emby provider beside it.
- Unused YAML rule providers are errors. Disabled/commented rules and Loon
  plugin declarations are not active rule references.

Banking uses the existing Orz-3 `exchangerate.png` URL in clients that expose a
service icon field: Stash `icon` and Egern `icon` (historical Loon Full used `img-url`).

## Content Validation Contract

The audit has two explicit scopes. With no artifact input it checks references,
provider declarations, canonical order and required final catch-alls; it does not
prove the contents of a remote rule set. Use this mode for focused reference
edits. For mixed-content migration or a domain/address acceptance gate, supply
the verified local output from the matching CustomRules `auto-build` revision:

```text
python scripts/audit_rule_policy_refs.py <ProxyConfig-repo> --artifact-root <verified-output> --external-artifacts <HTTPDNS-snapshot-mapping.json> --json
```

Only the exact `auto-build`/`refs/heads/auto-build` generated URLs map to these
local artifacts. A master, tag or other-ref URL is a source contract violation,
even when its relative file happens to exist locally. The standalone restored
HTTPDNS source under CustomRules `master/Stash/Rules/` is a separately bound
external snapshot, not a generated-artifact consumer.

Content mode expands active LIST rules and the same-set YAML accompanying each
MRS, verifies manifest rule counts/hashes, and checks every member's actual type
and early-address exception. YAML provider behavior must match the manifest's
payload encoding, even if a classical payload happens to contain only domains;
typed LIST/text inputs require classical behavior. MRS uses `mrs_behavior`.
It retains address/non-address runs for order checks
without embedding rule snapshots in the report. CustomRules `verify_build` and
its pinned-kernel MRS loading/equivalence gate must run first; this audit does not
decode the compiled MRS bytes itself. Reports identify this limit and record
text hashes, counts and types.

The external mapping is a local schema 1 JSON file. It contains `artifacts`, keyed
by the exact maintained public URL, with `path` relative to the mapping directory,
`format: "text"`, `behavior: "classical"`, and the file's `sha256`. Only these two
reviewed external sources are accepted:

- `Stash-HTTPDNS-Block`: `https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BlockHttpDNS/BlockHttpDNS.list`
- `Stash-HTTPDNS-Loon-Extra`: `https://raw.githubusercontent.com/SchweppesSoda/CustomRules/master/Stash/Rules/HTTPDNS.Loon-Extra.list`

The caller obtains those public snapshots explicitly; the auditor never fetches
them. Keep snapshots and the mapping in temporary output, not in this skill.
Unavailable inputs, missing policy/matcher fields, unknown rule types, compound
artifact syntax and unreviewed external sources return incomplete coverage (exit
2). Empty external HTTPDNS snapshots are incomplete even with a matching hash;
only a manifest-declared NonIP/Address partition side may be empty. Fully
observed type, hash or order violations return failure (exit 1). Exit 0
requires all requested checks and the six canonical profiles to be complete.
`--policy` filters the displayed references, not the shared content/order gates.

## Mihomo Kernel Validation Contract

After behavioral changes to Mihomo profiles, validate the changed profiles and
affected generated derivatives with the pinned Mihomo version and archive
checksum declared by CustomRules. Comments or documentation alone do not need
a kernel run. Expand to other profiles only for shared parser/template changes
or evidence of a shared failure.
Use an isolated working directory for each profile, seed `GeoSite.dat`, and run
`mihomo -t -f`. A YAML parser only proves syntax; the kernel check additionally
loads Mihomo fields, groups, rules, and the geosite-backed fake-IP filters. It
does not replace rule-order, undefined-policy, provider-type, or URL audits.

The bundled `scripts/validate_mihomo_configs.py` accepts repeatable `--config`
paths relative to the repository. Example (substitute verified local paths):

```text
python scripts/validate_mihomo_configs.py <repo> --mihomo <verified-kernel> --geosite <GeoSite.dat> --config Mihomo/AutoMihomo.Mobile.yaml
```

Run from this skill directory. With no `--config`, the helper checks its default
Mobile and OpenWrt baselines, plus SafeMihomo only when that legacy file exists.
An explicit `--config` remains required even if the selected file is missing.
Use the broader default mode only when needed. Missing tooling is a
reported verification limit, not a reason to run unrelated tests.

## Common Policy Targets

- Hard-coded: `DIRECT`, `REJECT`.
- Mihomo/Stash top-level inline proxy names are also valid rule targets in the
  same profile; a rule does not have to point to a proxy group.
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
