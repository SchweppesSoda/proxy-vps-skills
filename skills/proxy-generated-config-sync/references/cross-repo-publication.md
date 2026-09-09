# Cross-Repository Publication

The ProxyConfig and CustomRules repositories publish related but distinct
surfaces. Keep the relationship visible without copying rule data or secret
sources into the other repository.

## Publication graph

```text
ProxyConfig Mihomo Mobile + airport manifest
        │
        └─ Airport DNS writer
             ├─ CustomRules master: marked AirportServers sources
             └─ ProxyConfig: Stash/Loon Airport DNS markers

CustomRules master: reviewed sources/catalogs/toolchain
        │
        └─ Auto Build Rules writer (auto-build lock)
             └─ CustomRules auto-build: YAML/MRS/LIST + manifests/checksums
                    │
                    └─ ProxyConfig client rule providers
```

Provider Compatibility is a private ProxyConfig pipeline. It reads the
reviewed canonical profile and non-secret provider policy, writes only its
owned client markers, and delegates the WAN2 whole-file rendering to the
OpenWrt WAN2 generator. It does not publish provider capability URLs or
CustomRules rule data.

## Airport DNS sequence

Use the repository workflow and CLI as the source of execution details. The
safe publication sequence is:

1. Resolve both repository roots and read the generated-writer index,
   `AIRPORT_DOMAINS_AUTOMATION.md`, the airport manifest, and the active
   workflow.
2. Validate all local and external target markers, source shape, and shrink
   guards before fetching anything. Stage every replacement in memory or a
   same-directory temporary file.
3. Run the Airport DNS tests and the Stash/Loon/CustomRules validators. Enforce
   the declared four-output allowlist: two marked CustomRules sources and two
   ProxyConfig DNS blocks.
4. Publish the reviewed CustomRules source changes to `master` only through
   the workflow's scoped credentials. The deploy key is runner-temporary and
   never belongs in the manifest, repository files, or output.
5. Publish the staged ProxyConfig DNS blocks. A later CustomRules auto-build
   then publishes the public rule artifacts from `master` to `auto-build`.

There is no atomic commit across repositories. If the external source push
succeeds but the local push fails, preserve the source commit and report the
partial state; the next reviewed run must reconcile it. Do not invent a
rollback that could erase an external review or generated artifact.

## CustomRules source and artifact boundary

- `master` owns reviewed `sources/`, build scripts, tests, workflows, modules,
  and other non-rule resources.
- `auto-build` owns generated rule artifacts and their metadata, including
  `manifest.json`, `SOURCES.json`, and `SHA256SUMS`.
- Client rule consumers use the branch/path declared in their own canonical
  configuration. Do not switch a consumer between `master` and `auto-build`
  merely to make a URL look similar.
- AirportServers and AirportServersCTC are DNS-only sources. Their pinned CTC
  entries stay outside the generated marker.

## Secret-safe inspection

Capability URLs and tokens are inputs to the private writer, not review data.
Use the writer's discovery/masking path and report provider IDs or redacted
path shapes only. Prefer file-name or structural searches that do not print
values; never paste a raw URL into a log, JSON index, commit message, or final
report. A failure should identify the provider and failure class, not the
credential-bearing value.

## Handoff checks

Validate local rule/reference changes immediately where possible; live artifact
verification waits for the relevant build. After a generated client change,
run that client's applicable checks. Use the global audit only for requested
global coverage or evidence of cross-pipeline drift. Report local source,
generated artifact and consumer publication state separately. Existing session
authorization covers its stated publication scope; otherwise prepare a validated
local result and request authorization only for the external action.
