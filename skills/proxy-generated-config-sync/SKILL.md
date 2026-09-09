---
name: proxy-generated-config-sync
description: Coordinate ProxyConfig/CustomRules generators, owned outputs, locks and source-to-artifact publication. Use when changing or regenerating an affected writer scope.
---

# Generated configuration routing

Resolve the active repositories. Read `Sub-Store/AGENTS.md` and the affected entry in `Sub-Store/config/generated-writers.json`; follow that writer's current workflow and automation reference. The index routes to implementation, not a second provider database.

## Route

- Marker/field ownership, shared files, derivatives or writer changes: [writer contract](references/generated-writer-contract.md).
- Airport DNS cross-repository writes or CustomRules source/artifact publication: [publication contract](references/cross-repo-publication.md).
- Group membership, DNS semantics or rule order: the corresponding domain skill only if that semantic decision is also in scope.

## Work and finish

Operate only on the affected pipeline and its downstream derivatives. Use its repository-owned CLI; never hand-edit outputs or duplicate its parser/transaction logic. Preserve manual ranges, diff allowlists and shared-file locks. Missing/ambiguous markers or required input/validation failure means no installation. Index `validators` are locators, never executable shell text.

Requested canonical changes authorize their safe local generation and checks. Prepare and validate outputs through the existing writer transaction, then install within its declared scope. Publication/deployment follows session authorization; prepare the local result before seeking missing external authorization. Keep credentials and raw capability values out of reports and errors.

Complete when relevant writer/semantic checks pass and only intended scopes change; assess no-op byte/mtime behavior when writer code changes. A global consistency audit is needed only for a requested global review or evidence of cross-pipeline drift. Report canonical edits, generated outputs and publication status separately, including partial cross-repository outcomes.
