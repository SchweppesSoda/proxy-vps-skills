---
name: proxy-groups
description: Maintain ProxyConfig provider identities and proxy/policy group definitions or membership. Rule remaps to existing groups belong to proxy-rule-policy-routing.
---

# Proxy groups

Start from the requested provider/group and its direct consumers. Resolve the active repository and skill paths; preserve UTF-8, names, order and manual settings.

## Route

- Source URL/path/collection update, add/split, rename/delete, or unfamiliar client shape: read the relevant section of [group model](references/proxyconfig-group-model.md).
- A visible policy rename with rule consumers also needs `proxy-rule-policy-routing`; a source hostname that is a node-resolution input also needs `proxy-dns-routing`.
- A changed owned marker, derivative, writer input requiring regeneration, or publication needs `proxy-generated-config-sync`. Merely sharing a file with a writer does not.

## Work and finish

Keep source → collection → artifact → consumer identities separate. Source maintenance does not imply a visible rename. For rename/deletion trace aliases and consumers in all applicable clients before removing the old identity; for a local membership edit inspect that group and its consumers. Preserve intentional Safe/Lite differences and retained LKG data (`managed=false` is not permission to delete it).

Use repository URL tools where applicable and mask capability values. Finish the requested canonical edits and applicable regeneration, then verify changed references and client syntax. Use `scripts/audit_proxy_refs.py <repo> --target <name>` when its reference report helps; a pre-edit/full audit is optional. Its filter focuses output, not necessarily every internal check. Report unrelated findings separately and disclose pending generated/publication work. Routine local decisions and checks need no additional review stop.
