from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


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
