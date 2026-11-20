# ProxyConfig Group and Provider Model

## Maintained surfaces

- Mihomo profiles are discovered under `Mihomo/`; the active canonical inputs
  include `AutoMihomo.Mobile.yaml` and `AutoMihomo.OpenWrt.yaml`, while
  `SafeMihomo.yaml` may intentionally be minimal.
- Stash and both Egern profiles have distinct provider and policy shapes.
  Loon remains available in history only.

## Identity graph

```text
subscription/source → collection → published artifact → client consumer
```

Search and record each edge before a rename, deletion, split, or source-only
update. A provider URL/path, Sub-Store collection, cache path, node prefix,
published artifact, visible child group, and policy consumer are separate
objects. The fact that two names look alike is not evidence that they can be
merged.

## Client shapes

- Mihomo: `proxy-providers` define sources; `proxy-groups` consume provider
  names or other groups. Mobile, OpenWrt, and Safe can intentionally differ.
- Stash: Mihomo-like provider/group structures with Stash-specific overrides
  and rule consumers.
- Egern: `policy_groups` and `external` provider pools use Egern-specific
  filters and `auto_test`/`fallback` semantics.

## Ordered groups and probes

Use the current repository contract for the panel, business candidates, regional
timings and SNTP rate filters. Check both the displayed group order and the order
of each selector's candidates. The first candidate sets the fresh-import
default. An airport's automatic region and a cross-airport automatic group test
different sets of exits.

In Mihomo and Stash, give identical ordered lists a shared YAML sequence
anchor. Each business still has its own selector. For probe options, compose
mapping anchors from distinct fields so the repository's strict YAML loader
can reject duplicate keys. A sequence alias supplies the whole list. YAML
does not splice one sequence into another. Keep lists with different defaults,
regional restrictions or tail choices distinct. Use native expanded policies in
Egern while its maintained profile readers require alias-free YAML.

Validate the resolved membership, timing units and provider filters for each
affected client. For a geographic split, check the final egress on representative
leaf names containing more than one location. Check each landing group’s allowed
front-hop regions separately from its exit filter. When a published leaf embeds an
old front-hop name, trace its exact artifact variant and keep that route working
through the rename. The shared subscription identity and cache may outlive the
visible name.

## Operation checklist

### Source-only update

Audit the old and new source host/path, provider key, collection, cache path,
prefix, and policy path. Change only source metadata when visible group names
are stable. Use `Sub-Store/tools/sync_provider_urls.py` and
`Sub-Store/tools/verify_provider_urls.py` when their existing modes cover the
requested source change. Redact capability URLs and tokens in all output.

### Add or split

Decide the source, collection, artifact, visible name, regions, filters,
prefix, flattening, and inclusion in region/service/relay aggregates. Update
only clients with the corresponding structure. If the source is shared, keep
one source identity and make the visible split explicit.

### Rename or delete

Find provider/source aliases, visible groups, region aggregators, service
groups, rule targets, DNS exceptions, comments, order documentation, and
generated consumers. Decide whether to remove, replace, or retain a temporary
alias. Never remove an LKG source or artifact merely because `managed=false`.

### Generated handoff

If the operation changes an owned marker, selected field, whole-file derivative,
writer input, or publication workflow, load
`proxy-generated-config-sync`. It verifies non-overlapping scope, shared
concurrency, transaction behavior, and the correct validator; this model
continues to supply the semantic group decision.

## Final report

Report files changed, old references removed, new references added, client
asymmetry intentionally retained, generated handoffs performed, and any
source/artifact decision deferred because the repository could not determine
it safely.
