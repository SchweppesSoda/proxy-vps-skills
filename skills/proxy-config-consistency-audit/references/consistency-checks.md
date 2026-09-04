# ProxyConfig Consistency Checks

## What counts as drift

- A provider/source or published artifact is missing from a client where parity
  is expected, or a consumer points at a stale identity.
- An airport-like region base has incomplete HK/TW/SG/JP/US coverage where the
  client contract requires those regions.
- A removed provider remains in a group, aggregate, rule, DNS projection,
  comment, cache path, or generated output without an intentional-retention
  record.
- A rule points to a policy group that does not exist, or a provider is
  defined but unused.
- Airport DNS inventory is mixed with Provider Compatibility suffixes/aliases,
  or a DNS projection is missing its intended resolver.
- `generated-writers.json` names a missing input, workflow, validator, target,
  duplicate marker, overlapping selector, or mismatched shared lock.
- A generated target differs from its canonical input/expected generator, a
  workflow diff exceeds its allowlist, or a generated result was hand-edited.
- Surge split differs from `Surge/AutoSurge.conf` outside the workflow's normal
  synchronization window.
- A CustomRules consumer uses the wrong branch or artifact family, or the
  source/build/checksum chain is incomplete.

## What may be intentional

- A client lacks a protocol or feature and therefore has no equivalent
  provider, DNS projection, or service rule.
- SafeMihomo and Loon Lite deliberately contain a reduced service set while
  preserving the applicable order.
- Surge split files are transiently stale while their workflow is queued or
  running; report this as generated drift, not a manual-edit instruction.
- Provider Compatibility and Airport DNS share Stash/Loon physical files but
  own distinct, non-overlapping marker pairs under the same concurrency lock.
- A provider can be client-specific because its source, collection, or
  protocol support differs.
- A manual/LKG entry remains outside a generated marker by explicit contract.

## Evidence and follow-up

Use file/line evidence and the generated-writer index to identify the owner.
Never paste capability-bearing values into the report; report a provider ID,
redacted path shape, or failure class. Suggested follow-ups:

- `proxy-groups` for provider identity, group membership, and source metadata;
- `proxy-dns-routing` for DNS semantics and manual projections;
- `proxy-rule-policy-routing` for policy targets and canonical rule order;
- `proxy-generated-config-sync` for marker/field/whole-file writers, locks,
  transactions, and cross-repository publication.
