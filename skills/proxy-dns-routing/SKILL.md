---
name: proxy-dns-routing
description: Maintain DNS routing across the user's Mihomo, Surge, Stash, Loon, and Egern configurations. Use for AirportServers, airport node-domain resolution, provider-specific DoH, Egern dns.forward, Mihomo proxy-server-nameserver-policy, Surge Host mappings, DNS leak handling, and HTTPDNS behavior. Ordinary DNS edits stay here; hand off to proxy-generated-config-sync when they change an automation writer, generated marker/field, whole-file derivative, or cross-repository publication.
---

# Maintain Proxy DNS Routing

Treat DNS changes as resolution-path changes, not simple text edits. Identify
which client resolves the hostname, whether it is a node server or app domain,
which upstream is selected, and whether the same semantic rule is represented
in each applicable client.

## Scope and writer boundary

This skill owns DNS semantics and per-client projections. It does not own the
Airport DNS or Provider Compatibility generator implementation. Load
`$proxy-generated-config-sync` with this skill when the task touches a writer
input, marker/field, shared file lock, transaction, or CustomRules publication.
A normal manual DNS mapping does not activate the generated-writer skill by
itself.

The two automated pipelines are independent:

```text
  Airport DNS inventory -> Stash/Loon Airport DNS markers + CustomRules sources
Provider Compatibility -> provider-compat markers in client configs
```

Their marker scopes and logic must not be conflated, even when they write the
same physical Stash or Loon file.

## First steps

1. Resolve `<proxyconfig-root>` from the current checkout and
   `<proxy-vps-skills-root>` from the skill checkout; do not assume a drive or
   copied installation path.
2. Read `Sub-Store/config/airport-domain-sources.json`,
   `Sub-Store/config/provider-compat/registry.json`, and
   `Sub-Store/config/generated-writers.json` when the task involves an
   automated source or generated output.
3. Run the bundled DNS audit before edits:

```powershell
& "<python>" "<proxy-vps-skills-root>/skills/proxy-dns-routing/scripts/audit_dns_routing.py" "<proxyconfig-root>" --airportservers
```

Add `--domain "<domain>"` for a focused view. Read
`references/dns-routing-model.md` before cross-client or AirportServers work.
4. Use UTF-8 reads and `rg` for exact, wildcard, provider, and remote-list
   references. Inspect capability-bearing values through the writer's masking
   path; do not print raw URLs or tokens.

## Semantic workflow

1. Classify each hostname as an airport node server, provider compatibility
   host/alias, app/service domain, or mixed use. Select the resolver based on
   the capability and bootstrapping path, not on the display name.
2. Compare all applicable surfaces: Mihomo Mobile/OpenWrt/Safe, Surge Full,
   Stash, Loon, and Egern. Client asymmetry is acceptable when the client or
   workflow lacks an equivalent feature; report it explicitly.
3. Edit minimal manual/canonical surfaces:
   - Egern `dns.upstreams` and `dns.forward`;
   - Mihomo `dns.proxy-server-nameserver-policy`, `nameserver`, and related
     resolver keys;
   - Surge Full `[Host]` and DNS keys; split Host output is generated from the
     full profile;
   - Stash/Loon manual DNS areas when no writer owns the target range.
4. For AirportServers or Provider Compatibility changes, invoke the
   repository-owned CLI and tests. Never hand-edit a generated marker or
   reconstruct its algorithm in the skill.
5. Re-run the DNS audit and the generated-writer checks when applicable, then
   report scanned clients, generated scopes, intentional exclusions, and any
   external CustomRules publication still pending.

## Resolver invariants

- Egern `dns.forward` values must exist under `dns.upstreams`.
- Mihomo proxy-node domains must not depend on a resolver that requires the
  proxy to be running first.
- Preserve wildcard style: Egern suffix matches, Mihomo `+.domain`, and
  Surge `*.domain = server:<resolver>` where the client supports it.
- Keep app DNS rules distinct from proxy-server/node-domain rules.
- Provider-specific DoH must remain present until every consumer is audited;
  removing an upstream because one mapping disappeared is unsafe.
- CTC-specific remote lists and pinned/manual entries are separate from the
  Airport DNS generated marker unless the active writer contract says
  otherwise.
