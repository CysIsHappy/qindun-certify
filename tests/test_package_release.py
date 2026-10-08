from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PACKAGER = _load("package_release", ROOT / "scripts" / "package_release.py")
INSTALLER = _load("qindun_release_installer_test", ROOT / "scripts" / "install.py")
BOOTSTRAP = _load(
    "qindun_release_bootstrap_test",
    ROOT / "bootstrap" / "qindun_release_verify.py",
)
SCANNER = _load("qindun_certify_release_test", ROOT / "scripts" / "qindun_certify.py")


class QindunReleasePackageTest(unittest.TestCase):
    def test_release_is_reproducible_installable_and_reports_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_archive, first_checksum = PACKAGER.build(Path(first))
            second_archive, second_checksum = PACKAGER.build(Path(second))
            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            self.assertEqual(first_checksum.read_text(), second_checksum.read_text())
            self.assertEqual(
                first_archive.with_suffix(".zip.manifest.json").read_bytes(),
                second_archive.with_suffix(".zip.manifest.json").read_bytes(),
            )
            with ZipFile(first_archive) as archive:
                names = set(archive.namelist())
            report = SCANNER.scan(first_archive)

        self.assertIn("qindun-certify/SKILL.md", names)
        self.assertIn("qindun-certify/LICENSE", names)
        self.assertIn("qindun-certify/SECURITY.md", names)
        self.assertIn("qindun-certify/CONTRIBUTING.md", names)
        self.assertIn("qindun-certify/CHANGELOG.md", names)
        self.assertIn("qindun-certify/qindun", names)
        self.assertIn("qindun-certify/scripts/qindun_certify.py", names)
        self.assertIn("qindun-certify/agents/openai.yaml", names)
        self.assertIn("qindun-certify/rules/current.json", names)
        self.assertNotIn("qindun-certify/rules/rules-2026.08.3.json", names)
        self.assertNotIn("qindun-certify/rules/rules-2026.09.2.json", names)
        self.assertNotIn("qindun-certify/rules/rule-corpus-2026.09.2.json", names)
        current_bundle = json.loads(
            (ROOT / "rules/current.json").read_text(encoding="utf-8")
        )["current"]
        current_payload = json.loads(
            (ROOT / "rules" / current_bundle).read_text(encoding="utf-8")
        )
        current_corpus = current_payload["evidence_policy"]["rule_test_corpus"]
        self.assertIn(f"qindun-certify/rules/{current_bundle}", names)
        self.assertIn(f"qindun-certify/rules/{current_corpus}", names)
        self.assertIn("qindun-certify/rules/qindun-rule-bundle-v1.schema.json", names)
        self.assertIn("qindun-certify/rules/qindun-rule-corpus-v1.schema.json", names)
        self.assertIn("qindun-certify/scripts/qindun.py", names)
        self.assertIn("qindun-certify/scripts/qindun_benchmark.py", names)
        self.assertIn("qindun-certify/scripts/qindun_dependencies.py", names)
        self.assertIn("qindun-certify/scripts/qindun_external.py", names)
        self.assertIn("qindun-certify/scripts/qindun_review.py", names)
        self.assertIn("qindun-certify/scripts/qindun_sarif.py", names)
        self.assertIn("qindun-certify/scripts/qindun_trust.py", names)
        self.assertIn("qindun-certify/scripts/qindun_verify.py", names)
        self.assertIn("qindun-certify/action.yml", names)
        self.assertIn("qindun-certify/references/qindun-local-report-v3.schema.json", names)
        self.assertIn("qindun-certify/references/qindun-external-evidence-v1.schema.json", names)
        self.assertIn("qindun-certify/integrations/clawscan.yml", names)
        self.assertIn("qindun-certify/rules/external-taxonomy-map-v1.json", names)
        self.assertIn("qindun-certify/references/qindun-signed-report-v1.schema.json", names)
        self.assertIn("qindun-certify/references/qindun-signed-report-v2.schema.json", names)
        self.assertIn("qindun-certify/scripts/install.py", names)
        self.assertNotIn("qindun-certify/tests/test_qindun_certify.py", names)
        self.assertNotIn("qindun-certify/scripts/package_release.py", names)
        self.assertNotIn("qindun-certify/bootstrap/qindun_release_verify.py", names)
        # Exact copies of the running analyzer are inside the existing tool
        # trust boundary. Target names and manifests cannot grant that trust.
        self.assertEqual(report["scan_status"], "completed")
        self.assertEqual(report["local_grade_preview"], "B")
        self.assertTrue(report["coverage"]["complete"])
        self.assertEqual(report["coverage"]["incomplete_reasons"], [])
        self.assertEqual(report["coverage"]["statistics"]["trusted_internal_files"], 5)
        self.assertTrue(all(item["disposition"] == "candidate" for item in report["findings"]))

    def test_release_versions_stay_in_sync(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertEqual(version, "0.7.7")
        self.assertIn(f'version: "{version}"', skill)

    def test_release_rejects_symlinked_content(self) -> None:
        original_root = PACKAGER.ROOT
        original_paths = PACKAGER.INCLUDED_PATHS
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "skill"
                references = root / "references"
                references.mkdir(parents=True)
                outside = Path(directory) / "outside.txt"
                outside.write_text("not part of the skill", encoding="utf-8")
                (references / "linked.txt").symlink_to(outside)
                PACKAGER.ROOT = root
                PACKAGER.INCLUDED_PATHS = ("references",)
                with self.assertRaisesRegex(ValueError, "符号链接"):
                    PACKAGER.release_files()
        finally:
            PACKAGER.ROOT = original_root
            PACKAGER.INCLUDED_PATHS = original_paths

    def test_release_cli_requires_signature_or_explicit_development_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    PACKAGER.main(["--output-dir", directory])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(
                PACKAGER.main(["--output-dir", directory, "--unsigned-development-build"]),
                0,
            )

    @unittest.skipUnless(
        importlib.util.find_spec("cryptography") is not None,
        "cryptography is required for release signature tests",
    )
    def test_signed_release_manifest_binds_archive_and_installed_files(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        private_raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_key = base64.b64encode(
            private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dist"
            archive, _checksum = PACKAGER.build(
                output,
                source_commit="a" * 40,
                signing_private_key=base64.b64encode(private_raw).decode("ascii"),
                signing_key_id="qindun-release-test",
            )
            manifest_path = archive.with_suffix(".zip.manifest.json")
            signature_path = archive.with_suffix(".zip.manifest.sig.json")
            public_key_path = Path(directory) / "trusted-release-public-key"
            public_key_path.write_text(public_key, encoding="utf-8")
            verified_manifest, members, fingerprint = BOOTSTRAP.verify_release(
                archive,
                manifest_path=manifest_path,
                signature_path=signature_path,
                public_key_path=public_key_path,
            )
            changed_archive_dir = Path(directory) / "changed"
            changed_archive_dir.mkdir()
            changed_archive = changed_archive_dir / archive.name
            changed_archive.write_bytes(archive.read_bytes() + b"changed-after-verify")
            with self.assertRaisesRegex(ValueError, "原始 ZIP 与发布清单不一致"):
                BOOTSTRAP.extract_verified(
                    changed_archive,
                    Path(directory) / "must-not-extract",
                    members,
                    verified_manifest,
                )
            verified_root = BOOTSTRAP.extract_verified(
                archive,
                Path(directory) / "verified",
                members,
                verified_manifest,
            )
            self.assertTrue((verified_root / "qindun").is_file())
            self.assertEqual(len(fingerprint), 64)
            verified_installer = _load(
                "qindun_verified_release_installer_test",
                verified_root / "scripts" / "install.py",
            )
            installed, _backup = verified_installer.install(
                Path(directory) / "installed-skills",
                release_manifest=manifest_path,
                release_signature=signature_path,
                release_public_key=public_key,
                release_archive=archive,
            )
            self.assertTrue((installed / "qindun").is_file())
            original_manifest = manifest_path.read_text(encoding="utf-8")
            extracted = Path(directory) / "extracted"
            with ZipFile(archive) as package:
                package.extractall(extracted)
            root = extracted / "qindun-certify"
            manifest_document = json.loads(manifest_path.read_text(encoding="utf-8"))
            for item in manifest_document["files"]:
                (root / item["path"]).chmod(int(item["mode"], 8))

            manifest = INSTALLER.verify_release(
                root=root,
                manifest_path=manifest_path,
                signature_path=signature_path,
                expected_public_key=public_key,
                archive_path=archive,
            )
            self.assertEqual(manifest["source_commit"], "a" * 40)
            self.assertEqual(
                json.loads(signature_path.read_text(encoding="utf-8"))["signing_key_id"],
                "qindun-release-test",
            )
            original_signature = signature_path.read_text(encoding="utf-8")
            tampered_signature = json.loads(original_signature)
            tampered_signature["signing_key_id"] = "qindun-release-attacker"
            signature_path.write_text(json.dumps(tampered_signature), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "发布清单签名无效"):
                INSTALLER.verify_release(
                    root=root,
                    manifest_path=manifest_path,
                    signature_path=signature_path,
                    expected_public_key=public_key,
                    archive_path=archive,
                )
            signature_path.write_text(original_signature, encoding="utf-8")
            skill_path = root / "SKILL.md"
            skill_path.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "权限与签名清单不一致"):
                INSTALLER.verify_release(
                    root=root,
                    manifest_path=manifest_path,
                    signature_path=signature_path,
                    expected_public_key=public_key,
                    archive_path=archive,
                )
            unsafe_manifest = json.loads(original_manifest)
            next(item for item in unsafe_manifest["files"] if item["path"] == "SKILL.md")[
                "mode"
            ] = "0755"
            unsafe_signature = PACKAGER._sign_manifest(
                unsafe_manifest,
                private_key_value=base64.b64encode(private_raw).decode("ascii"),
                key_id="qindun-release-test",
            )
            manifest_path.write_bytes(PACKAGER._canonical_json(unsafe_manifest) + b"\n")
            signature_path.write_bytes(PACKAGER._canonical_json(unsafe_signature) + b"\n")
            with self.assertRaisesRegex(ValueError, "清单文件权限无效"):
                INSTALLER.verify_release(
                    root=root,
                    manifest_path=manifest_path,
                    signature_path=signature_path,
                    expected_public_key=public_key,
                    archive_path=archive,
                )
            manifest_path.write_text(original_manifest, encoding="utf-8")
            signature_path.write_text(original_signature, encoding="utf-8")
            skill_path.chmod(0o644)
            (root / "SKILL.md").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "签名清单不一致"):
                INSTALLER.verify_release(
                    root=root,
                    manifest_path=manifest_path,
                    signature_path=signature_path,
                    expected_public_key=public_key,
                    archive_path=archive,
                )

            with self.assertRaisesRegex(ValueError, "来源提交号"):
                PACKAGER.build(
                    output,
                    signing_private_key=base64.b64encode(private_raw).decode("ascii"),
                    signing_key_id="qindun-release-test",
                )


if __name__ == "__main__":
    unittest.main()
