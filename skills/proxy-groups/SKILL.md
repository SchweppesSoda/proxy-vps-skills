---
name: proxy-groups
description: Maintain proxy and policy groups plus provider source metadata across the user's Mihomo, Surge, Stash, Loon, and Egern configurations. Use when adding, deleting, renaming, splitting, or re-sourcing airport providers, self-hosted VPS groups, relay/dialer groups, region aggregates, service policies, provider URLs, provider paths, Sub-Store collections, node prefixes, or external-policy-name-prefix values. Do not use generated-writer coordination alone; hand off to proxy-generated-config-sync when the change crosses a generated marker, field, whole-file derivative, or publication workflow.
---

# Maintain Proxy Groups and Provider Identity

Treat every group or provider-source change as a reference-graph change. The
same commercial source may have different names or filters in Mihomo, Surge,
Stash, Loon, and Egern; verify each client rather than assuming inventory
parity.

## Scope and handoff

This skill owns semantic group membership, provider identity, source metadata,
and the consumers that refer to them. It does not own generated marker bodies,
WAN2, Surge split outputs, Airport DNS automation, or Provider Compatibility
rendering. When a task touches one of those surfaces, keep this skill loaded
for the group decision and load `$proxy-generated-config-sync` for writer
ownership and validation.

Also load `$proxy-dns-routing` when a provider source hostname is itself a
node-resolution input, and load `$proxy-rule-policy-routing` when a visible
group/policy rename has rule consumers. These are semantic handoffs even when
no generated writer is involved.

## First steps

1. Resolve `<proxyconfig-root>` from the current checkout; it must contain
   `Mihomo/`, `Surge/`, `Stash/`, `Loon/`, and `Egern/`.
2. Read files as UTF-8 and preserve comments, Chinese text, emoji, ordering,
   and existing hyphen/underscore spelling.
3. Run the bundled reference audit before edits. Use the skill checkout as
   `<proxy-vps-skills-root>` rather than assuming an installation path:

```powershell
& "<python>" "<proxy-vps-skills-root>/skills/proxy-groups/scripts/audit_proxy_refs.py" "<proxyconfig-root>" --target "<requested-name>"
```

4. Use `rg` across all five client directories for raw names, aliases,
   provider keys, cache paths, collection names, node prefixes, and comments.
   Read `references/proxyconfig-group-model.md` for the client shape and
   operation checklist.

## Provider identity chain

Keep these four identities separate and traceable:

```text
subscription/source -> Sub-Store collection -> published provider artifact -> client consumer
```

- A source URL or path is not automatically a visible policy/group rename.
- A collection name is not proof that two published artifacts are the same.
- A provider artifact is not a client policy group; search its consumers before
  changing or retiring it.
- Rename, delete, or split only after every identity and consumer is found in
  each applicable client.

`managed=false` means that a source is not currently under an active writer.
It does not authorize deleting a last-known-good (LKG) source, cache, or
published artifact. Retire an LKG only when the repository contract or the
user explicitly approves the retention change, using the native snapshot,
lock, and rollback behavior.

## Edit workflow

1. Classify the operation: source-only update, visible group change, provider
   add/delete, split, relay/dialer change, aggregate membership, or service
   policy change.
2. Build the old/new reference graph across Mihomo Mobile/OpenWrt/Safe where
   present, Surge full, Stash, Loon, and Egern. Keep intentionally minimal
   clients minimal; do not invent symmetry.
3. Separate canonical inputs from derived consumers. For Surge, edit
   `Surge/AutoSurge.conf`; its `Surge/Split Conf/AutoSurge/` files are generated
   by the repository workflow. For a generated group/provider marker, hand off
   before editing.
4. For source maintenance, use the repository-owned
   `Sub-Store/tools/sync_provider_urls.py` and
   `Sub-Store/tools/verify_provider_urls.py` when applicable. Verify the URL
   shape without printing capability URLs or tokens; source paths and prefixes
   remain non-secret policy data.
5. Apply the smallest client-specific edit set. Preserve established section
   order and comments, and update all consumers before removing a name.
6. Re-run the reference audit and targeted `rg` checks for old and new forms.
   If the change crossed a writer boundary, run the generated-writer checks and
   domain audits before declaring completion.

## Decisions that may require the user

Ask only when the repository cannot answer safely:

- provider source/path, collection, visible name, or prefix is ambiguous;
- a provider is shared by multiple collections/artifacts;
- a region or service aggregate should include or exclude a new group;
- a split requires a new source, a filter, or two visible groups over one
  source;
- the requested behavior could be `select`, `fallback`, `url-test`/`auto_test`,
  `smart`, or a client-specific equivalent.

## Validation

- Every changed provider/group has no dangling old references and the desired
  new references are present.
- Source-only changes leave visible names untouched unless explicitly asked.
- Provider URLs, policy paths, prefixes, and collection names agree with the
  intended source/artifact/consumer chain.
- All applicable clients pass their existing syntax/config checks.
- Surge full remains the source of truth; split drift is reported to the
  workflow rather than repaired by hand.
- Generated markers, fields, or whole-file derivatives are validated by
  `$proxy-generated-config-sync`; this skill does not silently take ownership
  of them.
