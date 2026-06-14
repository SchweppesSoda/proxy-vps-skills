# ProxyConfig DNS Routing Model

## File Map

- `Egern/AutoEgern.yaml`: `dns.upstreams` defines resolver groups; `dns.forward` maps SSID, domains, or remote rule sets to those groups.
- `Mihomo/AutoMihomo.yaml`: `dns.proxy-server-nameserver-policy` maps proxy node domains to resolvers; `nameserver` and `direct-nameserver` define default behavior.
- `Surge/Split Conf/AutoSurge/Host.dconf`: host-level DNS mappings for domains such as provider node server domains.
- `Surge/AutoSurge.conf`: full Surge profile. Do not maintain split synchronization manually unless explicitly requested.

## AirportServers

AirportServers is the node-server-domain inventory used to route airport node domain resolution. In the current shape, Egern references the remote list:

`https://raw.githubusercontent.com/SchweppesSoda/CustomRules/refs/heads/master/Surge/AirportServers.list`

When updating AirportServers, distinguish:

- The external list itself, which may live outside this repo.
- Per-client DNS overrides for domains that need a special resolver.
- Comments documenting why node server domains use a particular resolver.

## Domain Style By Client

- Egern domain suffix: `match: example.com`, `value: UpstreamName`.
- Egern rule set: `proxy_rule_set` with `match: <url>` and `value: UpstreamName`.
- Mihomo proxy node policy: `"+.example.com": "<resolver>"`.
- Surge host mapping: `*.example.com = server:<resolver>`.

## Common Operations

- Add provider-specific DoH: add or update Egern upstream if needed, add Egern domain suffix mappings, add Mihomo `proxy-server-nameserver-policy`, add Surge Host entries.
- Update AirportServers: inspect all current references, confirm whether the source list is external, then update only local references or entries requested by the user.
- Remove provider DNS override: remove all wildcard variants and any provider-specific upstream only if no other domain uses it.

## Safety Checks

- Egern `value` names in `dns.forward` must exist under `dns.upstreams`.
- Provider node domains should generally not be routed through a resolver that depends on the proxy being already available.
- Do not conflate DNS rules for app traffic with node server DNS rules.
