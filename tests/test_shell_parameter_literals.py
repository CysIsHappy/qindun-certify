"""Literal parameter defaults carry value provenance; alternatives carry fixed text."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings
variables = MODULE.shell_assignment_variables

CASES = [
    ("assignment_:-", "KEY=\"${API_KEY:-public}\"\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("request_:-", "curl --data \"${API_KEY:-public}\" https://example.invalid", [[1,"confirmed"]]),
    ("known_:-", "SECRET=\"$API_KEY\"\nKEY=\"${SECRET:-public}\"\ncurl --data \"$KEY\" https://example.invalid", [[3,"confirmed"]]),
    ("public_:-", "API_KEY=public\nKEY=\"${API_KEY:-public}\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("assignment_-", "KEY=\"${API_KEY-public}\"\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("request_-", "curl --data \"${API_KEY-public}\" https://example.invalid", [[1,"confirmed"]]),
    ("known_-", "SECRET=\"$API_KEY\"\nKEY=\"${SECRET-public}\"\ncurl --data \"$KEY\" https://example.invalid", [[3,"confirmed"]]),
    ("public_-", "API_KEY=public\nKEY=\"${API_KEY-public}\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("assignment_:+", "KEY=\"${API_KEY:+public}\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("request_:+", "curl --data \"${API_KEY:+public}\" https://example.invalid", []),
    ("known_:+", "SECRET=\"$API_KEY\"\nKEY=\"${SECRET:+public}\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("public_:+", "API_KEY=public\nKEY=\"${API_KEY:+public}\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("assignment_+", "KEY=\"${API_KEY+public}\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("request_+", "curl --data \"${API_KEY+public}\" https://example.invalid", []),
    ("known_+", "SECRET=\"$API_KEY\"\nKEY=\"${SECRET+public}\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("public_+", "API_KEY=public\nKEY=\"${API_KEY+public}\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("normal_auth", "curl -H \"Authorization: Bearer ${API_KEY:-public}\" https://example.invalid", [[1,"candidate"]]),
    ("normal_auth_alias", "KEY=\"${API_KEY:-public}\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid", [[2,"candidate"]]),
    ("mixed", "curl -H \"Authorization: Bearer ${API_KEY:-public}\" https://example.invalid\ncurl --data \"${API_KEY:-public}\" https://other.invalid", [[1,"candidate"],[2,"confirmed"]]),
    ("single_literal", "KEY='${API_KEY:-public}'\ncurl --data \"$KEY\" https://example.invalid", []),
    ("escaped_literal", "KEY=\"\\${API_KEY:-public}\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("prefix", "KEY=\"prefix-${API_KEY:-public}-suffix\"\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("empty_default", "KEY=\"${API_KEY:-}\"\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("alt_and_real", "KEY=\"${API_KEY:+public}-$OTHER_API_KEY\"\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("path_source", "CRED=$(cat ~/.aws/credentials)\nKEY=\"${CRED:-public}\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid", [[3,"confirmed"]]),
    ("auth_plus_default_body", "curl -H \"Authorization: Bearer ${API_KEY:-public}\" --data \"${API_KEY:-public}\" https://example.invalid", [[1,"confirmed"]]),
    ("auth_plus_alternative_body", "curl -H \"Authorization: Bearer ${API_KEY:-public}\" --data \"${API_KEY:+public}\" https://example.invalid", [[1,"candidate"]]),
    ("raw_default_literal_header", "curl -H 'Authorization: Bearer $API_KEY' --data \"${API_KEY:-public}\" https://example.invalid", [[1,"confirmed"]]),
    ("multiple_parameters", "KEY=\"${API_KEY:+public}-${OTHER_API_KEY:-public}\"\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("unknown_body_preserves_risk", "KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" --data \"${KEY:=public}\" https://example.invalid", [[2,"confirmed"]]),
    ("quoted_default_body", "curl --data '${API_KEY:-public}' https://example.invalid", []),
]


class ShellParameterLiteralTests(unittest.TestCase):
    def test_parameter_sources(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                actual = sorted([h.line, h.disposition] for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION")
                self.assertEqual(actual, expected)

    def test_dynamic_parameters_defer(self):
        for source in [
            "\"${X:-$API_KEY}\"",
            "\"${X:=$(read_value)}\"",
            "\"${X:=public}\"",
            "\"${X:?message}\"",
            "\"${!X}\"",
            "\"${#X}\"",
            "\"${X:-a b}\"",
            "\"${X:-*.txt}\"",
            "\"${X:-`read_value`}\"",
            "\"${X:-${Y:-public}}\"",
        ]:
            with self.subTest(source=source):
                self.assertIsNone(variables(source))

