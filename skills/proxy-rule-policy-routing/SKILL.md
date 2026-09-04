---
name: proxy-rule-policy-routing
description: Maintain rule providers, rule order, and policy routing across the user's Mihomo, Surge, Stash, Loon, and Egern configurations. Use for service rules, rule-provider sources, rule ordering, and rule-to-policy mappings. Enforce the repository's precedence contracts and audit every target; hand off to proxy-generated-config-sync when a change crosses a generated writer, CustomRules publication, marker/field, or whole-file derivative.
---

# Maintain Rule Policy Routing

Treat every rule change as a cross-client policy contract. A rule target must
resolve to an existing policy group, its provider must have the right format,
and its position must preserve the canonical precedence. Keep this skill for
rule semantics and order; use `$proxy-generated-config-sync` for generated
ownership or publication.

Also load `$proxy-groups` when the rule-target change creates, deletes, or
renames a policy group. A target-only remap to an existing group stays in this
skill; a group-definition change is a joint operation.

## Canonical rule order

The full configuration order in
`references/rule-policy-model.md` is normative. Preserve, at minimum, the
contiguous finance sequence immediately after the last AI rule:

```text
AI -> PayPal -> Banking -> Crypto
```

Apple precedes regional TV; Asian TV precedes Global TV; CN Mainland TV is the
last media family; service IP rules follow service/domain rules and precede
broad CN IP/ASN/GEOIP rules. Safe and Lite profiles may be deliberate
subsequences, not accidental copies.

## CustomRules publication chain

Custom rule sources follow this identity chain:

```text
CustomRules master reviewed sources
        -> Auto Build Rules / auto-build branch artifacts
        -> Mihomo, Surge, Stash, Egern, and Loon consumers
```

`master` owns reviewed `sources/`, catalogs, toolchain, tests, workflows, and
non-rule resources. `auto-build` owns generated YAML/MRS/LIST artifacts and
their manifest/checksum metadata. Do not edit generated artifacts or switch a
consumer's branch merely to make URLs look consistent. If a task changes a
source file, builder, generated artifact, checksum, or publication workflow,
load `$proxy-generated-config-sync` and wait for the appropriate build/check
before treating the consumer as updated.

## First steps

1. Resolve `<proxyconfig-root>` and `<proxy-vps-skills-root>` from the active
   checkouts; never assume a hard-coded drive path.
2. Read `references/rule-policy-model.md`, then search definitions and
   consumers with `rg` across Mihomo, Stash, Surge, Loon, and Egern.
3. Run the full rule audit before edits:

```powershell
& "<python>" "<proxy-vps-skills-root>/skills/proxy-rule-policy-routing/scripts/audit_rule_policy_refs.py" "<proxyconfig-root>"
```

Use `--policy` filters only as an additional focused view. Use
`--require-generated-sync` after the repository's Surge Split workflow has
completed, not as a substitute for that workflow.
4. When Mihomo files are in scope, use the pinned toolchain declared by
   CustomRules and the bundled kernel validator; do not substitute an
   unverified executable from `PATH`.

## Edit workflow

1. Classify the operation: add/remove provider, add/remap rule, reorder a
   service block, change a policy target, or change a CustomRules source.
2. Audit old/new policy names, provider paths, client-specific rule shapes,
   and all consumers before editing.
3. Update service policy groups before adding a rule that targets them. Keep
   each full profile's canonical order and preserve intentionally minimal
   Safe/Lite clients.
4. For a CustomRules source change, modify the reviewed `master` source and
   invoke the repository builder/tests; do not hand-edit the `auto-build`
   result. For a Surge rule change, edit `Surge/AutoSurge.conf`; split files
   are generated outputs.
5. If the edit touches a generated writer input, marker/field, whole-file
   derivative, diff allowlist, or cross-repository publication, keep the
   generated-writer skill loaded and follow its transaction/lock checks.
6. Re-run the full rule audit, targeted reference searches, and applicable
   client/kernel validators. Report any consumer waiting for a downstream
   build or split synchronization.

## Decisions that may require the user

Ask only when the repository and canonical model cannot decide:

- which existing policy should receive a rule hit;
- whether a new service belongs before or after an existing block;
- whether to create a service policy group or reuse one;
- which remote/custom provider is approved for a new rule source;
- whether a missing client projection is intentional.

## Validation

- Every active rule target resolves to a defined group or built-in.
- Providers are referenced by rules when required and use the correct domain or
  IP behavior; unused providers are errors.
- Full profiles preserve the complete canonical order and the finance
  sequence; Safe/Lite remain valid subsequences with their documented tail.
- Loon tags remain sequential after reordering.
- CustomRules source, `auto-build` artifacts, branch/path, manifest, and
  checksums agree; consumers are not claimed current before the build passes.
- Surge split drift is reported until the workflow synchronizes it.
- Generated ownership and cross-repository publication are validated by
  `$proxy-generated-config-sync`, not by hand-edited output.
