# ProxyConfig Group and Provider Model

## Maintained surfaces

- Mihomo profiles are discovered under `Mihomo/`; the active canonical inputs
  include `AutoMihomo.Mobile.yaml` and `AutoMihomo.OpenWrt.yaml`, while
  `SafeMihomo.yaml` may intentionally be minimal.
- Surge's canonical full profile is `Surge/AutoSurge.conf`.
  `Surge/Split Conf/AutoSurge/` is generated output and is not a second source
  of truth.
- Stash, Loon, and Egern each have their own provider and policy shapes. Do
  not infer parity from a matching display name.

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
- Surge Full: `[Proxy Group]` contains providers and policy groups;
  `include-other-group` is the main aggregation mechanism. Split sections are
  generated from the full profile.
- Stash: Mihomo-like provider/group structures with Stash-specific overrides
  and rule consumers.
- Egern: `policy_groups` and `external` provider pools use Egern-specific
  filters and `auto_test`/`fallback` semantics.
- Loon: provider and policy sections plus Full/Lite rule consumers can be
  intentionally less symmetric than other clients.

## Operation checklist

### Source-only update

Audit the old and new source host/path, provider key, collection, cache path,
prefix, and policy path. Change only source metadata when visible group names
are stable. Verify with the repository-owned provider URL tools, and redact
capability URLs and tokens in all output.

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
