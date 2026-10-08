from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ENGINE = _load("qindun_review_engine_test", SCRIPTS / "qindun_certify.py")
REVIEW = _load("qindun_review_hardening_test", SCRIPTS / "qindun_review.py")


class QinDunReviewHardeningTest(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "jsonschema is required")
    def test_review_schema_accepts_new_accounting_and_historical_inputs(self) -> None:
        import jsonschema

        schema = json.loads((ROOT / "references/qindun-semantic-review-input-v1.schema.json").read_text())
        validator = jsonschema.Draft202012Validator(schema)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SKILL.md").write_text(
                "---\nname: demo\ndescription: demo\n---\nRun `python absent.py`\n", encoding="utf-8")
            payload = REVIEW.build(root, ENGINE.scan(root))
        validator.validate(payload)
        payload["unavailable_contexts"][0]["reason"] = "safe"
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate(payload)
        del payload["omitted_count"], payload["unavailable_contexts"]
        validator.validate(payload)

    def test_missing_entrypoints_are_counted_without_inventing_context(self) -> None:
        for zipped in (False, True):
            with self.subTest(zipped=zipped), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = "---\nname: demo\ndescription: demo\n---\nRun `python absent.py`\n"
                if zipped:
                    target = root / "sample.zip"
                    with ZipFile(target, "w") as archive:
                        archive.writestr("SKILL.md", source)
                else:
                    target = root
                    (root / "SKILL.md").write_text(source, encoding="utf-8")
                report = ENGINE.scan(target)
                index = next(i for i, item in enumerate(report["findings"])
                             if item["rule_id"] == "QINDUN.LOCAL.D3.UNSUPPORTED_ENTRYPOINT")
                payload = REVIEW.build(target, report)
                self.assertEqual(payload["candidate_count"], sum(
                    item["disposition"] == "candidate" for item in report["findings"]))
                self.assertIn({"finding_index": index, "reason": "missing_line"},
                              payload["unavailable_contexts"])
                self.assertEqual(payload["omitted_count"],
                                 payload["candidate_count"] - payload["included_count"])
                self.assertTrue(all(item["path"] != "absent.py" for item in payload["requests"]))

    def test_unavailable_and_invalid_locations_are_explicit_alongside_valid_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SKILL.md").write_text("---\nname: demo\ndescription: demo\n---\n", encoding="utf-8")
            report = ENGINE.scan(root)
            base = {"rule_id": "QINDUN.TEST", "dimension": "D3", "severity": "high",
                    "path": "SKILL.md", "line": 1, "summary": "test", "disposition": "candidate"}
            locations = [(None, "SKILL.md", "missing_line"), (0, "SKILL.md", "invalid_line"),
                         (-1, "SKILL.md", "invalid_line"), (True, "SKILL.md", "invalid_line"),
                         ("1", "SKILL.md", "invalid_line"), (99, "SKILL.md", "line_out_of_range"),
                         (1, "absent.py", "source_unavailable"),
                         (1, "../outside.py", "source_unavailable")]
            report["findings"] = [{**base, "disposition": "confirmed"}]
            report["findings"] += [{**base, "line": line, "path": path} for line, path, _ in locations]
            report["findings"].append(base)
            payload = REVIEW.build(root, report)
        self.assertEqual(payload["candidate_count"], 9)
        self.assertEqual(payload["included_count"], 1)
        self.assertEqual(payload["omitted_count"], 8)
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["unavailable_contexts"], [
            {"finding_index": index + 1, "reason": reason}
            for index, (_, _, reason) in enumerate(locations)])
        self.assertEqual(payload["requests"][0]["context"]["lines"][0], "---")

    def test_unlocated_overflow_is_bounded_and_counted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SKILL.md").write_text("---\nname: demo\ndescription: demo\n---\n", encoding="utf-8")
            report = ENGINE.scan(root)
            report["findings"] = [{"disposition": "candidate", "line": None} for _ in range(51)]
            payload = REVIEW.build(root, report)
        self.assertEqual(payload["candidate_count"], 51)
        self.assertEqual(payload["omitted_count"], 51)
        self.assertEqual(payload["included_count"], 0)
        self.assertEqual(len(payload["unavailable_contexts"]), 50)
        self.assertTrue(payload["truncated"])

    def test_candidate_count_and_truncation_use_total_before_slice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SKILL.md").write_text(
                "---\nname: demo\ndescription: demo\n---\n# Demo\n",
                encoding="utf-8",
            )
            report = ENGINE.scan(root)
            candidate = {
                "rule_id": "QINDUN.TEST.CANDIDATE",
                "dimension": "D3",
                "severity": "high",
                "path": "SKILL.md",
                "line": 1,
                "summary": "test",
                "disposition": "candidate",
            }
            report["findings"] = [dict(candidate) for _ in range(REVIEW.MAX_REQUESTS)]
            exact = REVIEW.build(root, report)
            report["findings"].append(dict(candidate))
            overflow = REVIEW.build(root, report)

        self.assertEqual(exact["candidate_count"], REVIEW.MAX_REQUESTS)
        self.assertFalse(exact["truncated"])
        self.assertEqual(overflow["candidate_count"], REVIEW.MAX_REQUESTS + 1)
        self.assertTrue(overflow["truncated"])
        self.assertEqual(overflow["included_count"], REVIEW.MAX_REQUESTS)


if __name__ == "__main__":
    unittest.main()
