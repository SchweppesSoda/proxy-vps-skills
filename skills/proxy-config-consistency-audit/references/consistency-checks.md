# ProxyConfig Consistency Checks

## What Counts As Drift

- A provider exists in one client but is absent from another client where parity is expected.
- An airport-like region base has some but not all of HK/TW/SG/JP/US for a client.
- A provider was removed but remains in `Others`, `MassData`, `Speedtest`, DNS, comments, or modules.
- A rule points to a policy group that does not exist in that client.

## What May Be Intentional

- A provider can be client-specific because a client lacks protocol support or uses a different Sub-Store collection.
- Surge split files may differ transiently if GitHub Actions regenerate them.
- Loon has a different subscription model and may not mirror Egern/Mihomo/Surge provider inventories.
- DNS overrides can be intentionally client-specific when only one client supports a desired expression.

## Suggested Follow-Up Skills

- Use `proxy-groups` for provider/group fixes.
- Use `proxy-dns-routing` for DNS and AirportServers fixes.
- Use `proxy-rule-policy-routing` for undefined or misrouted rule targets.
