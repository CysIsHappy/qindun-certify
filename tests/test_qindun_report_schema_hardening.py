from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


try:
    import jsonschema
except ImportError:  # pragma: no cover - release CI installs the validator
    jsonschema = None


ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "scripts"
SPEC = importlib.util.spec_from_file_location(
    "qindun_report_schema_engine_test",
    SCRIPTS / "qindun_certify.py",
)
assert SPEC is not None and SPEC.loader is not None
ENGINE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ENGINE
SPEC.loader.exec_module(ENGINE)


@unittest.skipIf(jsonschema is None, "jsonschema is required for formal report validation")
class QinDunReportSchemaHardeningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(
            (ROOT / "references/qindun-local-report-v3.schema.json").read_text(
                encoding="utf-8"
            )
        )
        cls.validator = jsonschema.validators.validator_for(cls.schema)(cls.schema)

    def _clean_report(self) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "SKILL.md").write_text(
                "---\nname: demo\ndescription: demo\n---\n# Demo\n",
                encoding="utf-8",
            )
            return ENGINE.scan(target)

    @staticmethod
    def _critical_finding() -> dict:
        return {
            "rule_id": "QINDUN.TEST.CONFIRMED_DANGER",
            "severity": "critical",
            "title": "test",
            "summary": "test",
            "path": "SKILL.md",
            "line": 1,
            "evidence": "redacted",
            "evidence_digest": "sha256:" + "0" * 64,
            "dimension": "D3",
            "rule_version": "test",
            "disposition": "confirmed",
            "source": "deterministic",
            "deterministic": True,
            "remediation": "修复测试风险后重新扫描。",
            "help_uri": "https://cwe.mitre.org/",
        }

    def test_real_clean_report_remains_valid(self) -> None:
        self.validator.validate(self._clean_report())

    def test_b_cannot_contain_high_or_confirmed_critical_finding(self) -> None:
        report = self._clean_report()
        report["findings"].append(self._critical_finding())
        with self.assertRaises(jsonschema.ValidationError):
            self.validator.validate(report)

    def test_d_requires_confirmed_deterministic_critical_finding(self) -> None:
        report = self._clean_report()
        report["local_grade_preview"] = "D"
        with self.assertRaises(jsonschema.ValidationError):
            self.validator.validate(report)

        report["findings"].append(self._critical_finding())
        self.validator.validate(report)


if __name__ == "__main__":
    unittest.main()
