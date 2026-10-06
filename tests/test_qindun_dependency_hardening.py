from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "scripts" / "qindun_dependencies.py"
SPEC = importlib.util.spec_from_file_location("qindun_dependencies_hardening_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
DEPENDENCIES = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DEPENDENCIES
SPEC.loader.exec_module(DEPENDENCIES)


class QinDunDependencyHardeningTest(unittest.TestCase):
    def test_empty_dependency_declarations_do_not_require_lock_files(self) -> None:
        package = DEPENDENCIES.extract([("package.json", b'{"name":"demo","version":"1.0.0"}')])
        python = DEPENDENCIES.extract(
            [("pyproject.toml", b'[project]\nname="demo"\nversion="1.0.0"\n')]
        )
        cargo = DEPENDENCIES.extract([("Cargo.toml", b'[package]\nname="demo"\nversion="1.0.0"\n')])
        gradle = DEPENDENCIES.extract([("build.gradle", b"plugins { id 'java' }\n")])

        for inventory in (package, python, cargo, gradle):
            self.assertTrue(inventory["complete"], inventory["errors"])
            self.assertEqual(inventory["package_count"], 0)

    def test_supported_declarations_must_exist_in_matching_lock(self) -> None:
        cases = [
            (
                [
                    ("Cargo.toml", b'[dependencies]\nserde="1"\n'),
                    (
                        "Cargo.lock",
                        b'[[package]]\nname="other"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n',
                    ),
                ],
                "serde",
            ),
            (
                [
                    ("composer.json", b'{"require":{"vendor/pkg":"^1"}}'),
                    ("composer.lock", b'{"packages":[{"name":"other/pkg","version":"1.0.0"}]}'),
                ],
                "vendor/pkg",
            ),
            (
                [
                    ("Gemfile", b"gem 'rack'\n"),
                    ("Gemfile.lock", b"GEM\n  specs:\n    other (1.0.0)\n"),
                ],
                "rack",
            ),
            (
                [
                    ("go.mod", b"module example.com/demo\nrequire github.com/acme/lib v1.0.0\n"),
                    ("go.sum", b"github.com/other/lib v1.0.0 h1:abc\n"),
                ],
                "github.com/acme/lib",
            ),
            (
                [
                    (
                        "pom.xml",
                        b"<project><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1</version></dependency></dependencies></project>",
                    ),
                    (
                        ".flattened-pom.xml",
                        b"<project><dependencies><dependency><groupId>org.other</groupId><artifactId>other</artifactId><version>1</version></dependency></dependencies></project>",
                    ),
                ],
                "org.example:demo",
            ),
            (
                [
                    ("build.gradle", b"dependencies { implementation 'org.example:demo:1.0' }\n"),
                    ("gradle.lockfile", b"org.other:other:1.0=runtimeClasspath\n"),
                ],
                "org.example:demo",
            ),
        ]

        for files, missing_name in cases:
            with self.subTest(missing_name=missing_name):
                inventory = DEPENDENCIES.extract(files)
                self.assertFalse(inventory["complete"])
                self.assertTrue(
                    any(missing_name in error for error in inventory["errors"]),
                    inventory["errors"],
                )

    def test_sbom_root_binds_exact_artifact_and_only_direct_dependencies(self) -> None:
        files = [
            ("package.json", b'{"dependencies":{"direct":"1.0.0"}}'),
            (
                "package-lock.json",
                json.dumps(
                    {
                        "packages": {
                            "node_modules/direct": {
                                "version": "1.0.0",
                                "resolved": "https://registry.npmjs.org/direct/-/direct-1.0.0.tgz",
                            },
                            "node_modules/transitive": {
                                "version": "2.0.0",
                                "resolved": "https://registry.npmjs.org/transitive/-/transitive-2.0.0.tgz",
                            },
                        }
                    }
                ).encode(),
            ),
        ]
        first_hash = "1" * 64
        second_hash = "2" * 64
        first = DEPENDENCIES.extract(files, artifact_sha256=first_hash)
        second = DEPENDENCIES.extract(files, artifact_sha256=second_hash)
        first_sbom = first["sbom"]
        second_sbom = second["sbom"]

        self.assertNotEqual(first_sbom["serialNumber"], second_sbom["serialNumber"])
        self.assertEqual(
            first_sbom["metadata"]["component"]["bom-ref"],
            f"urn:qindun:artifact:{first_hash}",
        )
        properties = {
            item["name"]: item["value"]
            for item in first_sbom["metadata"]["component"]["properties"]
        }
        self.assertEqual(properties["qindun:artifact-sha256"], first_hash)
        self.assertEqual(
            first_sbom["dependencies"][0]["dependsOn"],
            ["pkg:npm/direct@1.0.0"],
        )

    def test_directory_content_manifest_is_not_mislabeled_as_package_hash(self) -> None:
        content_manifest_sha256 = "3" * 64
        inventory = DEPENDENCIES.extract(
            [("package.json", b'{"name":"directory-demo"}')],
            content_manifest_sha256=content_manifest_sha256,
        )
        root = inventory["sbom"]["metadata"]["component"]
        properties = {item["name"]: item["value"] for item in root["properties"]}

        self.assertEqual(
            root["bom-ref"],
            f"urn:qindun:content-manifest:{content_manifest_sha256}",
        )
        self.assertEqual(properties["qindun:artifact-sha256"], "unavailable")
        self.assertEqual(
            properties["qindun:content-manifest-sha256"],
            content_manifest_sha256,
        )

    def test_osv_skips_non_public_dependencies(self) -> None:
        dependencies = [
            {"ecosystem": "npm", "name": "public", "version": "1.0.0", "provenance": "public"},
            {"ecosystem": "npm", "name": "private", "version": "1.0.0", "provenance": "private"},
            {"ecosystem": "npm", "name": "local", "version": "1.0.0", "provenance": "local"},
        ]

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def read(self, limit: int) -> bytes:
                return b'{"results":[{}]}'[:limit]

        with patch.object(DEPENDENCIES, "urlopen", return_value=Response()) as request:
            result = DEPENDENCIES.query_osv(dependencies)

        self.assertTrue(result["complete"], result["error"])
        self.assertEqual(result["total_queries"], 1)
        self.assertEqual(len(result["skipped_dependencies"]), 2)
        request.assert_called_once()

    def test_ambiguous_lock_sources_never_reach_osv_request_body(self) -> None:
        cases = {
            "npm-workspace": [
                (
                    "package-lock.json",
                    json.dumps(
                        {
                            "packages": {
                                "packages/secret": {
                                    "name": "@corp/secret",
                                    "version": "1.0.0",
                                }
                            }
                        }
                    ).encode(),
                )
            ],
            "pipfile-git": [
                (
                    "Pipfile.lock",
                    json.dumps(
                        {
                            "default": {
                                "corp-pip": {
                                    "version": "==1.2.3",
                                    "git": "ssh://git@internal/corp-pip.git",
                                }
                            }
                        }
                    ).encode(),
                )
            ],
            "uv-virtual": [
                (
                    "uv.lock",
                    b'[[package]]\nname="corp-uv"\nversion="0.1.0"\n'
                    b'source={virtual="."}\n'
                    b'[[package]]\nname="corp-typo"\nversion="0.1.0"\n'
                    b'source={registry="https://pypi.org.evil/simple"}\n',
                )
            ],
            "gem-git": [
                (
                    "Gemfile.lock",
                    b"GIT\n  remote: ssh://git@internal/corp-gem.git\n"
                    b"  specs:\n    corp-gem (1.0.0)\n",
                )
            ],
            "go-private": [
                ("go.sum", b"github.com/corp/private-go v1.2.3 h1:abc\n")
            ],
            "nuget-unknown": [
                (
                    "packages.lock.json",
                    json.dumps(
                        {
                            "dependencies": {
                                "net8.0": {"Corp.NuGet": {"resolved": "1.2.3"}}
                            }
                        }
                    ).encode(),
                )
            ],
            "gradle-unknown": [
                ("gradle.lockfile", b"corp.internal:gradle-secret:1.2.3=runtime\n")
            ],
        }
        private_packages = []
        for name, files in cases.items():
            with self.subTest(name=name):
                inventory = DEPENDENCIES.extract(files)
                self.assertTrue(inventory["complete"], inventory["errors"])
                self.assertTrue(inventory["packages"])
                self.assertNotEqual(inventory["packages"][0]["provenance"], "public")
                private_packages.extend(inventory["packages"])
        private_packages.append(
            {
                "ecosystem": "npm",
                "name": "confirmed-public",
                "version": "1.0.0",
                "provenance": "public",
            }
        )
        private_packages.append(
            {"ecosystem": "npm", "name": "missing-provenance", "version": "1.0.0"}
        )
        request_bodies: list[dict] = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def read(self, limit: int) -> bytes:
                return b'{"results":[{}]}'[:limit]

        def open_osv(request, **_kwargs):
            request_bodies.append(json.loads(request.data))
            return Response()

        with patch.object(DEPENDENCIES, "urlopen", side_effect=open_osv):
            result = DEPENDENCIES.query_osv(private_packages)

        self.assertTrue(result["complete"], result["error"])
        self.assertEqual(
            request_bodies,
            [
                {
                    "queries": [
                        {
                            "package": {"ecosystem": "npm", "name": "confirmed-public"},
                            "version": "1.0.0",
                        }
                    ]
                }
            ],
        )
        serialized = json.dumps(request_bodies)
        for dependency in private_packages[:-2]:
            self.assertNotIn(dependency["name"], serialized)
        self.assertNotIn("missing-provenance", serialized)

    def test_osv_global_time_budget_stops_remaining_batches(self) -> None:
        dependencies = [
            {
                "ecosystem": "PyPI",
                "name": f"pkg-{index}",
                "version": "1.0.0",
                "provenance": "public",
            }
            for index in range(201)
        ]
        with (
            patch.object(DEPENDENCIES.time, "monotonic", side_effect=[0.0, 2.0, 2.0]),
            patch.object(DEPENDENCIES, "urlopen") as request,
        ):
            result = DEPENDENCIES.query_osv(
                dependencies,
                overall_timeout_seconds=1.0,
            )

        self.assertFalse(result["complete"])
        self.assertEqual(result["failed_batches"], [1, 2, 3])
        self.assertEqual(result["completed_queries"], 0)
        request.assert_not_called()

    def test_osv_total_response_budget_preserves_completed_batch(self) -> None:
        dependencies = [
            {
                "ecosystem": "PyPI",
                "name": f"pkg-{index}",
                "version": "1.0.0",
                "provenance": "public",
            }
            for index in range(101)
        ]
        first_body = json.dumps(
            {"results": [{"vulns": [{"id": "OSV-FIRST"}]}] + [{}] * 99}
        ).encode()
        second_body = b'{"results":[{}]}'
        calls = 0

        class Response:
            def __init__(self, body: bytes) -> None:
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def read(self, limit: int) -> bytes:
                return self.body[:limit]

        def open_osv(_request, **_kwargs):
            nonlocal calls
            calls += 1
            return Response(first_body if calls == 1 else second_body)

        with patch.object(DEPENDENCIES, "urlopen", side_effect=open_osv):
            result = DEPENDENCIES.query_osv(
                dependencies,
                max_total_response_bytes=len(first_body) + 5,
            )

        self.assertEqual(calls, 2)
        self.assertFalse(result["complete"])
        self.assertEqual(result["completed_queries"], 100)
        self.assertEqual(result["failed_batches"], [2])
        self.assertEqual(result["vulnerabilities"][0]["id"], "OSV-FIRST")
        self.assertLessEqual(result["total_response_bytes"], len(first_body) + 6)


if __name__ == "__main__":
    unittest.main()
