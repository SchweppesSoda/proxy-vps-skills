---
name: proxy-dns-routing
description: Maintain ProxyConfig DNS resolvers, node-domain resolution and manual DNS mappings. HTTPDNS rule targets or blocking modules alone are outside this skill.
---

# Proxy DNS routing

Identify the hostname, resolving client, node versus application use, and intended upstream. Search the affected mapping and resolver consumers before changing them; expand across clients only for shared DNS behavior.

## Route

- Resolver syntax, wildcard projection, cross-client behavior or AirportServers: read the relevant section of [DNS model](references/dns-routing-model.md).
- Airport DNS/Provider Compatibility inputs or generated output: read the active manifest/registry and use `proxy-generated-config-sync` for that writer.
- HTTPDNS rule order or policy target: use `proxy-rule-policy-routing`. A module's enabled state is a separate user setting.

## Work and finish

Edit manual/canonical ranges. Egern forwards must reference defined upstreams; proxy-node bootstrap must not depend on an already running proxy. Keep application and node DNS separate. Before deleting an upstream, find its remaining consumers. Keep Airport DNS inventory distinct from compatibility aliases and pinned/manual CTC entries.

Verify the changed resolution path, wildcard form and references. Use `scripts/audit_dns_routing.py <repo> --domain <domain>` for a focused report; add `--airportservers` only for inventory/list changes. Filters do not guarantee that internal checks are limited to that domain. Run the selected writer's checks only when involved. No mandatory pre-edit or global audit. Complete safe local edits and report intentional asymmetry, unavailable runtime verification, or pending publication without exposing capability URLs or tokens.
