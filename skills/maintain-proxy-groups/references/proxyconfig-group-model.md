# ProxyConfig Group Model

## File Map

Primary configuration files:

- `Mihomo/AutoMihomo.yaml`
- `Surge/AutoSurge.conf`
- `Surge/Split Conf/AutoSurge/ProxyGroup.dconf`
- `Surge/Split Conf/AutoSurge/Rule.dconf`
- `Egern/AutoEgern.yaml`

Prefer split Surge files for targeted group edits when they are the maintained source; verify whether `AutoSurge.conf` is generated or manually kept in sync before editing both.

## Taxonomy

Airport providers are subscription-backed pools such as `MESL`, `BitzNet`, `SNTP`, `LinkCube`, `Flower`, `CTC02`, `LiangXin`, and `OixCloud`. Inventory differs by client: verify in each file instead of assuming parity.

Self-hosted providers are VPS or private pools such as `PO0_HK`, `PO0_TW`, `PO0_JP`, `PO0_US`, `DMIT_PRO`, `DMIT_EB`, and `CUSTOM_JP`. Visible groups include names such as `PO0-HK`, `DMIT-PRO`, `Core JP`, and `Edge JP`.

Relay/Dialer groups are candidates used as previous hops or dialer proxies for Residential/Landed traffic. Mihomo names are Dialer-oriented; Surge and Egern use Relay-oriented names. They include PO0, Core/Edge, DMIT, regional auto/manual groups, `Others`, and `DIRECT`.

Region groups collect airport child groups by geography:

- Airport child groups: `MESL-HK`, `Bitz-JP`, `SNTP-US`, `OixCloud-SG`, etc.
- Region automatic groups: `HK-Auto`, `TW-Auto`, `SG-Auto`, `JP-Auto`, `US-Auto`.
- Region manual groups: `HK-Manual`, `TW-Manual`, `SG-Manual`, `JP-Manual`, `US-Manual`.

Service groups route rule hits. Examples include `Proxy`, `MyProxy`, `MyDirect`, `Emby`, `AI Suite`, `Telegram`, `YouTube`, `Netflix`, `Apple`, `Microsoft`, `Steam`, and `Speedtest`.

Special pools:

- `MassData` contains higher-traffic airport region groups and is reused by mass/media service groups.
- `Others` pulls unmatched nodes from airport providers and excludes known region keywords.
- `SNTP-Auto` and `SNTP-Manual` are special SNTP regional pools.

## Client Shapes

Mihomo:

- Providers live under `proxy-providers`.
- Groups live under `proxy-groups`.
- Anchors define reusable service lists, but mixed groups still have hand-written lists.
- Airport child behavior uses `type: select`, `url-test`, or `fallback`; future `smart` must be explicitly requested and checked against Mihomo support.

Surge:

- Providers and groups are line-based in `[Proxy Group]`.
- `include-other-group` is the main reuse mechanism.
- Hidden templates include `AllRegions`, `AllRegions-Mass`, `AllAirports`, and `AllOf-*`.
- Airport child behavior is `select`, `url-test`, or `fallback`.

Egern:

- Groups live under `policy_groups`.
- Provider pools use `external`.
- Child groups use `select`, `auto_test`, or `fallback`.
- Service groups repeat policy lists instead of relying on YAML anchors, so additions/removals often touch many blocks.
- `prev_hop` is used for Residential/Landed relay chains.

## Hot Spots By Operation

Add an airport such as `TAG`:

- Add hidden provider source in every target client.
- Add per-region child groups for the chosen regions and behavior.
- Insert child groups into region auto/manual aggregators.
- Decide whether to add to `AllAirports`/`Speedtest`.
- Decide whether to add to `MassData`.
- Add provider to `Others` and update the region exclusion regex if needed.
- Add DNS exceptions only if the provider requires custom node-domain resolution.
- Preserve provider ordering relative to similar airports.

Delete an airport such as `OIX`/`OixCloud`:

- Remove provider source, per-region child groups, region aggregator entries, `AllAirports`/`Speedtest`, `MassData`, and `Others`.
- Search for provider-specific DNS entries, panels, comments, and order-scheme documentation.
- Re-run the audit for raw aliases: `OIX`, `Oix`, `OixCloud`, `OixCloud-Provider`, `OixCloud-HK`, `OixCloud_Snell`.

Add a self-hosted group such as `PO0 SG`:

- Add provider source and visible group.
- Decide whether it is part of Relay/Dialer chains.
- Decide whether it belongs in `Proxy`/`AllRegions`, mass lists, `Emby`, `Speedtest`, `AI Suite`, or only manual use.
- Use region naming consistent with existing `PO0-HK/TW/JP/US`.

Delete a self-hosted group such as `DMIT PRO`:

- Remove provider source and visible group.
- Remove from Relay/Dialer lists, `Proxy`/`AllRegions`, `Emby`, `Speedtest`, service comments, and any order-scheme documentation.
- Audit both hyphen and underscore forms: `DMIT-PRO`, `DMIT_PRO`, `DMIT PRO`, `DMIT_PRO_Provider`.

Split a self-hosted group such as `Core JP` or `Edge JP`:

- Identify whether both visible groups currently share one provider such as `CUSTOM_JP`.
- Ask whether the split means separate provider URLs, provider filters, or only separate visible groups over the same source.
- Update all consumers of the old group and provider deliberately; do not duplicate the same provider under new names unless requested.
- If keeping compatibility, document any alias group and validate it is intentional.

## Final Report Expectations

After edits, report:

- Files changed.
- Old references removed and new references added.
- Any unresolved or intentionally retained references.
- Questions deferred because the user did not specify a behavior or client-specific support was unclear.

