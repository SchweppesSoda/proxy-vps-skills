# ProxyConfig DNS Routing Model

## Client surfaces and source of truth

- Mihomo Mobile/OpenWrt/Safe profiles use
  `dns.proxy-server-nameserver-policy`, `nameserver`, and related resolver
  keys. Discover the maintained profiles under `Mihomo/`; do not use a generic
  legacy profile path as a universal source.
- Surge Full uses `Surge/AutoSurge.conf` for canonical `[Host]` and DNS
  settings. `Surge/Split Conf/AutoSurge/Host.dconf` is generated output.
- Stash uses its YAML DNS mappings; Loon uses its `[Host]`/resolver sections;
  Egern uses `dns.upstreams` and `dns.forward`.

The five clients can have intentional differences. Record why a projection is
missing instead of silently manufacturing parity.

## Two automated writers

### Airport DNS

`Sub-Store/config/airport-domain-sources.json` selects the reviewed Mihomo
Mobile profile and non-secret source metadata. The Airport DNS CLI discovers
live node server domains and replaces only the `AUTO-GENERATED AIRPORT DNS`
marker in:

- `Stash/AutoStash.yaml`;
- `Loon/AutoLoon.conf`.

The same run replaces the `AUTO-GENERATED PROVIDER DOMAINS` marker in
CustomRules `sources/manual/AirportServers.yaml` and
`AirportServersCTC.yaml`. CTC pinned entries remain outside the marker. The
external source and local projections are separate repository targets but one
reviewed writer/publication sequence.

### Provider Compatibility

`Sub-Store/config/provider-compat/registry.json` and its provider JSON files
describe non-secret policy. The Provider Compatibility CLI writes only its
`AUTO-GENERATED PROVIDER-COMPAT REAL-IP` and
`AUTO-GENERATED PROVIDER-COMPAT HOSTS` ranges in the applicable Mihomo,
Stash, Egern, and Loon files. It does not own Airport DNS mappings, Surge
Host output, or CustomRules rule sources. Its OpenWrt baseline output is
passed to the WAN2 generator; WAN2 remains a whole-file derivative owned by
that generator.

Both writers can touch Stash and Loon physically, so they must use the same
`generated-file-writers-main` concurrency group and non-overlapping markers.
The generated-writer index is the compact ownership map; the automation docs,
CLI, and tests provide the detailed parser/render/transaction contract.

## Domain projection rules

- Airport node-server inventory is not the same as provider fake-IP/hosts
  compatibility. Do not add compatibility suffixes to AirportServers merely
  because both are DNS-related.
- Egern's AirportServers remote rule set is an external projection. A CTC
  remote list or provider-specific Egern mapping is not automatically changed
  by the Airport DNS CLI.
- Stash Airport DNS maps suffixes to its domestic resolver list; Loon projects
  the corresponding host mappings to its configured resolver. Use the active
  manifest and writer rather than copying one client's syntax to another.
- Surge Host mappings for ordinary queries do not prove that proxy-server
  hostname resolution is covered. Preserve the documented client limitation
  and report any unresolved proxy-server requirement.

## Validation checklist

1. Check the requested domain/mapping; use `audit_dns_routing.py --domain` when
   helpful. Include `--airportservers` only when the inventory or lists change.
   A focused search is sufficient for a narrow, understood manual mapping.
2. Check Egern upstream references and wildcard forms, Mihomo policy keys,
   Surge Full Host entries, and manual Stash/Loon sections.
3. If a writer is involved, run its dry-run/check mode, marker/ownership test,
   client validators, and `git diff --check` as declared by its workflow.
4. Confirm no raw capability URL, token, credential, or full provider source
   was copied into a manifest, generated index, log, or report.
5. Report external CustomRules changes separately; no local audit can pretend
   that an unpushed cross-repository source is already published.
