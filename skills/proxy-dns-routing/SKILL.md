---
name: proxy-dns-routing
description: Maintain DNS routing in the user's ProxyConfig repository for Egern, Mihomo, and Surge. Use when updating AirportServers DNS forwarding, airport node-domain DNS policies, provider-specific DoH overrides, DNS upstream groups, Surge Host mappings, Egern dns.forward rules, Mihomo proxy-server-nameserver-policy entries, or DNS leak/HTTPDNS-related routing behavior. Always inspect AirportServers references and run the bundled DNS audit before editing.
---

# Maintain Proxy DNS Routing

## Core Rule

Treat DNS changes as resolution-path changes, not simple text edits. Before editing, identify which client resolves the hostname, which upstream or DoH is selected, whether the rule targets node server domains or app traffic, and whether the same domain needs entries in Egern, Mihomo, Surge, or an external AirportServers list.

This skill does not maintain Surge split synchronization. If Surge split files differ from `Surge/AutoSurge.conf`, report the drift and leave synchronization to the repository's GitHub Action.

## First Steps

1. Locate the ProxyConfig repo. Prefer the current workspace when it contains `Mihomo/`, `Surge/`, and `Egern/`.
2. Read files as UTF-8. Do not trust mojibake shown by default PowerShell output.
3. Run the DNS audit helper before edits:

```powershell
& "<python>" "<skill>/scripts/audit_dns_routing.py" "D:\GitRepo\ProxyConfig" --domain ctcxianyu.com --domain 525536.xyz
```

For AirportServers-specific work, run:

```powershell
& "<python>" "<skill>/scripts/audit_dns_routing.py" "D:\GitRepo\ProxyConfig" --airportservers
```

Read `references/dns-routing-model.md` before making cross-client DNS edits or updating AirportServers behavior.

## Required Decisions

Ask only when the repo cannot answer the decision:

- Whether a domain is a proxy node server domain, an app/service domain, or both.
- Which resolver should be authoritative: default domestic DNS, international DoH, provider-specific DoH, system/router DNS, or a named Egern upstream.
- Whether AirportServers should be updated externally, referenced remotely, or replaced by local per-client entries.
- Whether a change should apply to all clients or only to the client named by the user.

## Edit Workflow

1. Audit current entries for every raw domain and list URL, including wildcard variants such as `example.com`, `*.example.com`, and `+.example.com`.
2. Classify the change:
   - AirportServers list update: node server domain inventory.
   - Provider-specific DNS override: a provider requires a special DoH.
   - Resolver policy change: upstream choice or ordering changes.
   - DNS-leak hardening: default/proxy/direct resolver strategy changes.
3. Edit the minimal client-specific DNS surfaces:
   - Egern: `dns.upstreams` and `dns.forward`.
   - Mihomo: `dns.proxy-server-nameserver`, `proxy-server-nameserver-policy`, `nameserver`, or `direct-nameserver`.
   - Surge: `[Host]` / `Host.dconf`, general DNS keys, and comments when they document active behavior.
4. Re-run `audit_dns_routing.py` and `rg` for all domains and list URLs.
5. Report client coverage, intentional asymmetry, and any AirportServers update that must happen outside this repo.

## Validation

- DNS audit shows the intended resolver for each requested domain or AirportServers URL.
- `rg` confirms no stale wildcard variant remains.
- The change does not silently remove provider-specific DoH entries.
- Egern upstream names referenced by `dns.forward` exist in `dns.upstreams`.
- Mihomo policy entries use the correct wildcard style (`+.domain`) and Surge host entries use the correct style (`*.domain = server:...`).
