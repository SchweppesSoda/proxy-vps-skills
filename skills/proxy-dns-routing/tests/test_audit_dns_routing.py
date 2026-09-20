import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_dns_routing.py"
_SPEC = importlib.util.spec_from_file_location("audit_dns_routing_under_test", SCRIPT)
_AUDIT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _AUDIT
assert _SPEC.loader is not None
_SPEC.loader.exec_module(_AUDIT)


def write_file(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def write_json(root: Path, relative: str, document: object) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")


def make_client_fixture(root: Path) -> None:
    write_file(root, "Surge/Retired.conf", "[Host]\nretired.example = 1.1.1.1\n")
    write_file(root, "Egern/AutoEgern.yaml", """
        dns:
          upstreams:
            cn:
              - 1.1.1.1
          forward:
            - domain:
                match: api.example.com
                value: cn
          hosts:
            host.example.com: 1.2.3.4
    """)
    write_file(root, "Mihomo/AutoMihomo.Mobile.yaml", """
        dns:
          proxy-server-nameserver-policy:
            mobile.example.com: cn
          hosts:
            host.example.com: 1.2.3.4
    """)
    write_file(root, "Mihomo/AutoMihomo.OpenWrt.yaml", """
        dns:
          proxy-server-nameserver-policy:
            openwrt.example.com: cn
    """)
    write_file(root, "Mihomo/AutoMihomo.OpenWrt-WAN2.yaml", """
        dns:
          proxy-server-nameserver-policy:
            wan2-only.example.com: cn
    """)
    write_file(root, "Mihomo/AutoMihomo.yaml", """
        dns:
          proxy-server-nameserver-policy:
            base.example.com: cn
    """)
    write_file(root, "Mihomo/SafeMihomo.yaml", """
        dns:
          proxy-server-nameserver-policy:
            safe-only.example.com: cn
    """)
    write_file(root, "Loon/AutoLoon.conf", """
        [Host]
        loon.example.com = server:1.1.1.1
        [General]
        dns-server = https://dns.example/dns-query
    """)
    write_file(root, "Loon/Nested/Lite.conf", """
        [Host]
        loon-lite.example.com = server:1.1.1.1
    """)
    write_file(root, "Stash/AutoStash.yaml", """
        # BEGIN AUTO-GENERATED AIRPORT DNS
        dns:
          nameserver-policy:
            stash.example.com: cn
        # END AUTO-GENERATED AIRPORT DNS
        hosts:
          stash-host.example.com: 1.2.3.4
    """)
    write_json(
        root,
        "Sub-Store/config/generated-writers.json",
        {
            "schema": 1,
            "writers": [
                {
                    "id": "stash-airport",
                    "concurrency_group": "dns-build",
                    "targets": [
                        {
                            "repository": "ProxyConfig",
                            "path": "Stash/AutoStash.yaml",
                            "scope": "marker-pair",
                            "selector": "AUTO-GENERATED AIRPORT DNS",
                        }
                    ],
                }
            ],
        },
    )


class AuditDnsRoutingTests(unittest.TestCase):
    def test_uuid_credentials_are_redacted(self) -> None:
        value = "00000000-0000-7000-8000-000000000001"
        self.assertNotIn(value, _AUDIT.redact(value))
        samples = {
            "ssr://SSRSECRET",
            "wireguard://WG_SECRET@host.example:51820",
            "ssh://user:SSH_SECRET@host.example:22",
            "ws://user:WS_SECRET@host.example/path",
            "wss://user:WSS_SECRET@host.example/path",
            "quic://QUIC_SECRET@host.example:443",
            "httpdns://HTTPDNS_SECRET@host.example/query",
            '{"client_secret":"CLIENT_SECRET","refresh_token":"REFRESH_SECRET"}',
            "authorization: Bearer AUTH_SECRET",
            "proxy-authorization = Basic BASIC_SECRET",
        }
        rendered = json.dumps(_AUDIT.redact({sample: sample for sample in samples}))
        for forbidden in (
            "SSRSECRET",
            "WG_SECRET",
            "SSH_SECRET",
            "WS_SECRET",
            "WSS_SECRET",
            "QUIC_SECRET",
            "HTTPDNS_SECRET",
            "CLIENT_SECRET",
            "REFRESH_SECRET",
            "AUTH_SECRET",
            "BASIC_SECRET",
        ):
            self.assertNotIn(forbidden, rendered)

        structured = _AUDIT.redact(
            {
                "password": "short-password",
                "authorization": "Bearer short-auth",
                "nested": {
                    "token": 12345,
                    "client_secret": ["short-secret"],
                },
            }
        )
        self.assertEqual(structured["password"], "<redacted>")
        self.assertEqual(structured["authorization"], "<redacted>")
        self.assertEqual(structured["nested"]["token"], "<redacted>")
        self.assertEqual(structured["nested"]["client_secret"], "<redacted>")
        self.assertIn("password", structured)
        self.assertIn("authorization", structured)
        self.assertNotIn("wss://", rendered)

    def test_dynamic_clients_dns_sources_and_derived_skip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_client_fixture(root)
            payload = _AUDIT.audit(root, [], False)

            self.assertEqual(payload["exit_code"], 0)
            self.assertEqual(
                {item["client"] for item in payload["scanned"]},
                {"Egern", "Mihomo", "Loon", "Stash"},
            )
            skipped = {item["path"] for item in payload["skipped"]}
            self.assertIn("Mihomo/AutoMihomo.OpenWrt-WAN2.yaml", skipped)
            self.assertNotIn("Mihomo/SafeMihomo.yaml", skipped)
            hit_files = {item["file"] for item in payload["dns_hits"]}
            self.assertFalse(any("WAN2" in path or "Split Conf" in path for path in hit_files))
            self.assertIn("Mihomo/SafeMihomo.yaml", hit_files)
            self.assertIn("Loon/Nested/Lite.conf", {item["path"] for item in payload["scanned"]})
            hit_kinds = {item["kind"] for item in payload["dns_hits"]}
            self.assertIn("egern-domain", hit_kinds)
            self.assertIn("mihomo-proxy-server-nameserver-policy", hit_kinds)
            self.assertIn("loon-host", hit_kinds)
            self.assertIn("stash-nameserver-policy", hit_kinds)
            self.assertTrue(any(item["scope"] == "whole-file" for item in payload["generated"]))
            self.assertTrue(any(item["scope"] == "marker" for item in payload["generated"]))

            filtered = _AUDIT.audit(root, ["api.example.com"], False)
            self.assertEqual(filtered["exit_code"], 0)
            self.assertTrue(filtered["dns_hits"])
            self.assertTrue(
                all(item["key"].casefold().endswith("api.example.com") for item in filtered["dns_hits"])
            )
            self.assertFalse(
                any(item["kind"].endswith("dns-setting") for item in filtered["dns_hits"])
            )

    def test_missing_writer_contract_is_environment_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(root, "Egern/AutoEgern.yaml", "dns:\\n  forward: []\\n")
            payload = _AUDIT.audit(root, [], False)

            self.assertEqual(payload["exit_code"], 2)
            self.assertIn(
                "Sub-Store/config/generated-writers.json",
                {item["path"] for item in payload["skipped"]},
            )
            self.assertTrue(
                any("contract absent" in item for item in payload["environment_errors"])
            )

    def test_contract_marker_overlap_and_concurrency_violations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(root, "Mihomo/AutoMihomo.Mobile.yaml", """
                # BEGIN AUTO-GENERATED PROVIDER-COMPAT
                dns:
                  proxy-server-nameserver-policy:
                    one.example.com: cn
                # BEGIN AUTO-GENERATED PROVIDER-COMPAT
                # END AUTO-GENERATED PROVIDER-COMPAT
                # END AUTO-GENERATED PROVIDER-COMPAT
            """)
            write_json(
                root,
                "Sub-Store/config/generated-writers.json",
                {
                    "writers": [
                        {
                            "id": "marker-owner",
                            "concurrency_group": "group-a",
                            "targets": [
                                {
                                    "repository": "ProxyConfig",
                                    "path": "Mihomo/AutoMihomo.Mobile.yaml",
                                    "scope": "marker-pair",
                                    "selector": "AUTO-GENERATED PROVIDER-COMPAT",
                                }
                            ],
                        },
                        {
                            "id": "whole-owner",
                            "concurrency_group": "group-b",
                            "targets": [
                                {
                                    "repository": "ProxyConfig",
                                    "path": "Mihomo/AutoMihomo.Mobile.yaml",
                                    "scope": "whole-file",
                                }
                            ],
                        },
                    ]
                },
            )
            payload = _AUDIT.audit(root, [], False)
            kinds = {item["kind"] for item in payload["issues"]}

            self.assertEqual(payload["exit_code"], 1)
            self.assertIn("marker-duplicate", kinds)
            self.assertIn("scope-overlap", kinds)
            self.assertIn("concurrency-mismatch", kinds)

    def test_airportservers_and_payload_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(root, "Loon/AutoLoon.conf", """
                [Host]
                secret.example.com = https://user:token123@dns.example/dns-query?token=token123
            """)
            write_file(root, "Surge/AirportServers.list", """
                # local inventory intentionally has no repeated token
            """)
            write_json(
                root,
                "Sub-Store/config/airport-domain-sources.json",
                {"AirportServers": ["https://user:token123@airport.example/domains"]},
            )
            write_json(
                root,
                "Sub-Store/config/generated-writers.json",
                {
                    "writers": [
                        {
                            "id": "external",
                            "targets": [
                                {
                                    "repository": "OtherRepo",
                                    "path": "generated/out.conf",
                                }
                            ],
                        }
                    ]
                },
            )

            payload = _AUDIT.audit(root, [], True)
            rendered = json.dumps(payload, ensure_ascii=False)

            self.assertEqual(payload["exit_code"], 0)
            self.assertTrue(payload["airportservers"])
            self.assertNotIn("token123", rendered)
            self.assertNotIn("https://user:", rendered)
            self.assertTrue(
                any(item["kind"] == "local-airportservers-list" for item in payload["airportservers"])
            )
            self.assertTrue(
                any(item["kind"] == "local-airportservers-list" and item["line"] == 0 for item in payload["airportservers"])
            )
            self.assertTrue(
                any(item["kind"] == "airportservers-reference" for item in payload["airportservers"])
            )


if __name__ == "__main__":
    unittest.main()
