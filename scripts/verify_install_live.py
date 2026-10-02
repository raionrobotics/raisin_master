#!/usr/bin/env python3
"""Exercise the install CLI against a running local OTA server, without mocks.

Creates uniquely named packages, ZIPs, archives and tags through the public API,
runs the repository's CLI in isolated workspaces, then deletes its own records.
Logs and a JSON report stay in the output directory. No robot build is attempted.

Usage: python3 scripts/verify_install_live.py --output /tmp/raisin-install-live
Requires an SSH key already registered with the local OTA server.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid
import zipfile

import requests
import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from raisin_ota import client as ota


class Verification:
    def __init__(self, endpoint, output):
        self.endpoint = endpoint.rstrip("/")
        self.output = output
        output.mkdir(parents=True, exist_ok=True)
        self.prefix = "codex-install-" + uuid.uuid4().hex[:10]
        self.names = {
            name: self.prefix.replace("-", "_") + "_" + name
            for name in ("gui", "raibo2", "core", "leaf", "extra", "missing")
        }
        self.resources = {
            "archives": [],
            "archive-tags": [],
            "manifests": [],
            "packages": [],
        }
        self.results = []
        self.environment = os.environ.copy()
        for key in tuple(self.environment):
            if key.startswith("RAISIN_ROBOT") or key == "RAISIN_ARCHIVE_NAME":
                self.environment.pop(key)
        self.environment.update(
            RAISIN_OTA_ENDPOINT=self.endpoint, RAISIN_DEV_ALLOW_LOOPBACK_HTTP="1"
        )
        os.environ.update(
            RAISIN_OTA_ENDPOINT=self.endpoint, RAISIN_DEV_ALLOW_LOOPBACK_HTTP="1"
        )
        auth = output / "auth"
        auth.mkdir(exist_ok=True)
        ota.configure(ota.OtaContext(auth, "ubuntu", "24.04", "x86_64"))
        token = ota.authenticate()
        if not token:
            raise RuntimeError("SSH authentication against local OTA failed")
        self.headers = {"Authorization": "Bearer " + token}
        self.auth_cache = auth / ".ota_token_cache.json"
        self.session = requests.Session()
        self.session.trust_env = False
        self.platform = "ubuntu-24.04-x86_64"
        self.entries = {}
        self.archives = {}

    def api(self, method, path, **kwargs):
        headers = {**self.headers, **kwargs.pop("headers", {})}
        response = self.session.request(
            method,
            self.endpoint + path,
            headers=headers,
            timeout=20,
            allow_redirects=False,
            **kwargs,
        )
        if response.status_code >= 300:
            raise RuntimeError(f"{method} {path}: HTTP {response.status_code}")
        return ota._unwrap_response(response.json()) if response.content else None

    def remember(self, kind, resource):
        self.resources[kind].append(resource["id"])
        (self.output / "resources.json").write_text(
            json.dumps(self.resources, indent=2)
        )
        return resource

    def publish(
        self,
        package_id,
        name,
        version,
        dependencies=(),
        *,
        marker="original",
        embedded_version=None,
        bad_yaml=False,
        build_type="release",
    ):
        artifact = io.BytesIO()
        with zipfile.ZipFile(artifact, "w", zipfile.ZIP_DEFLATED) as package:
            package.writestr(
                "release.yaml",
                (
                    "[broken: yaml"
                    if bad_yaml
                    else yaml.safe_dump(
                        {
                            "version": embedded_version or version,
                            "dependencies": list(dependencies),
                        }
                    )
                ),
            )
            package.writestr("payload.txt", f"{name}=={version}:{marker}:{self.prefix}")
            executable = zipfile.ZipInfo("bin/check-install")
            executable.external_attr = 0o100755 << 16
            package.writestr(executable, "#!/bin/sh\nexit 0\n")
        content = artifact.getvalue()
        digest = hashlib.sha256(content).hexdigest()
        self.api(
            "POST",
            "/blobs",
            headers={"Content-Type": "application/zip", "x-content-sha256": digest},
            data=content,
        )
        response = self.api(
            "POST",
            f"/packages/{package_id}/manifests",
            json={
                "blobHash": digest,
                "platform": self.platform,
                "buildType": build_type,
                "sourceType": "jenkins",
            },
        )  # Dependencies deliberately exist only in the ZIP.
        manifest = response["manifest"]
        if manifest["hash"] not in self.resources["manifests"]:
            self.resources["manifests"].append(manifest["hash"])
            (self.output / "resources.json").write_text(
                json.dumps(self.resources, indent=2)
            )
        return {
            "packageId": package_id,
            "packageName": name,
            "manifestHash": manifest["hash"],
            "tagName": "v" + version,
        }

    def archive(self, label, entries, *, omit_versions=False, build_type="release"):
        name = self.prefix + ("-debug" if build_type == "debug" else "")
        data = self.api(
            "POST",
            "/archives",
            json={
                "name": name,
                "version": label,
                "platform": self.platform,
                "manifestOnly": True,
                "packages": [
                    {
                        key: value
                        for key, value in entry.items()
                        if key != "tagName" or not omit_versions
                    }
                    for entry in entries
                ],
            },
        )
        self.remember("archives", data)
        self.archives[label] = data
        return data

    def set_tag(self, name, archive):
        existing = getattr(self, "tags", {}).get(name)
        if existing:
            self.api(
                "PATCH",
                f"/archive-tags/{existing['id']}/promote",
                json={"archiveIds": [archive["id"]]},
            )
        else:
            data = self.api(
                "POST",
                "/archive-tags",
                json={
                    "archiveName": self.prefix,
                    "tagName": name,
                    "tagType": "alias",
                    "archiveIds": [archive["id"]],
                },
            )
            self.remember("archive-tags", data)
            if not hasattr(self, "tags"):
                self.tags = {}
            self.tags[name] = data

    def fixtures(self):
        ids = {}
        for label, name in self.names.items():
            if label != "missing":
                ids[label] = self.remember(
                    "packages",
                    self.api(
                        "POST",
                        "/packages",
                        json={
                            "name": name,
                            "description": "PR 118 isolated install verification",
                        },
                    ),
                )["id"]
        for version in ("1.0.0", "2.0.0"):
            entries = {}
            for label in ids:
                dependencies = {
                    "gui": [self.names["core"] + ">=1"],
                    "raibo2": [self.names["core"] + ">=1"],
                    "core": [self.names["leaf"] + ">=1"],
                }.get(label, [])
                entries[label] = self.publish(
                    ids[label], self.names[label], version, dependencies
                )
            self.entries[version] = entries
            self.archive(version, list(entries.values()))
        # The timestamp endpoint also omits package version in the live API.
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.archive(
            "versionless", list(self.entries["2.0.0"].values()), omit_versions=True
        )
        self.archive("same-content", list(self.entries["2.0.0"].values()))
        republished = dict(self.entries["2.0.0"])
        republished["gui"] = self.publish(
            ids["gui"],
            self.names["gui"],
            "2.0.0",
            [self.names["core"] + ">=1"],
            marker="republished",
        )
        self.archive("republished", list(republished.values()))
        for label, options, dependencies in (
            ("missing-dependency", {}, [self.names["missing"]]),
            ("constraint-conflict", {}, [self.names["core"] + "<1"]),
            ("bad-yaml", {"bad_yaml": True}, []),
            ("version-mismatch", {"embedded_version": "9.0.0"}, []),
        ):
            variant = dict(self.entries["2.0.0"])
            variant["gui"] = self.publish(
                ids["gui"], self.names["gui"], "2.0.0", dependencies, **options
            )
            self.archive(label, list(variant.values()))
        self.archive(
            "debug",
            [self.publish(ids["gui"], self.names["gui"], "2.0.0", build_type="debug")],
            build_type="debug",
        )
        self.set_tag("stable", self.archives["1.0.0"])
        self.set_tag("latest", self.archives["2.0.0"])

    def workspace(self, label, clone=None):
        path = self.output / label
        if clone:
            shutil.copytree(clone, path, symlinks=True)
        else:
            path.mkdir()
            shutil.copyfile(REPO / "raisin.py", path / "raisin.py")
            for module in ("commands", "raisin_ota"):
                (path / module).symlink_to(REPO / module, target_is_directory=True)
            (path / "configuration_setting.yaml").write_text("user_type: user\n")
            shutil.copyfile(self.auth_cache, path / ".ota_token_cache.json")
            (path / ".ota_token_cache.json").chmod(0o600)
        return path

    def source(self, path, label, version="1.0.0", dependencies=()):
        source = path / "src" / self.names.get(label, label)
        source.mkdir(parents=True, exist_ok=True)
        (source / "release.yaml").write_text(
            yaml.safe_dump({"version": version, "dependencies": list(dependencies)})
        )
        return source

    def inventory(self, path, build_type="release"):
        base = path / "release/install"
        if not base.exists():
            return {}
        result = {}
        for file in base.glob(f"*/ubuntu/24.04/x86_64/{build_type}/release.yaml"):
            result[file.relative_to(base).parts[0]] = yaml.safe_load(file.read_text())[
                "version"
            ]
        return result

    def package_path(self, path, label, build_type="release"):
        return (
            path
            / "release/install"
            / self.names[label]
            / "ubuntu/24.04/x86_64"
            / build_type
        )

    def tree(self, path):
        base = path / "release/install"
        return str(base.resolve()) if base.exists() else None

    def contents(self, path, base=None):
        base = base if base is not None else path / "release/install"
        return (
            {
                str(file.relative_to(base)): (
                    hashlib.sha256(file.read_bytes()).hexdigest(),
                    stat.S_IMODE(file.stat().st_mode),
                )
                for file in base.rglob("*")
                if file.is_file()
            }
            if base.exists()
            else {}
        )

    def run(
        self,
        label,
        path,
        arguments,
        *,
        expected=0,
        packages=None,
        log_contains=(),
        log_excludes=(),
        preserve=False,
        select_archive=True,
        reused_archive=None,
    ):
        previous = self.tree(path)
        inventory = self.inventory(path)
        contents = self.contents(path) if preserve or reused_archive else None
        if select_archive:
            arguments = [*arguments, "--archive-name", self.prefix]
        started = time.monotonic()
        process = subprocess.run(
            [sys.executable, str(path / "raisin.py"), "install", *arguments],
            env=self.environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
        )
        (self.output / (label + ".log")).write_text(process.stdout)
        errors = []
        if process.returncode != expected:
            errors.append(f"exit {process.returncode}, expected {expected}")
        if packages is not None and self.inventory(path) != packages:
            errors.append("installed package inventory differs")
        if process.returncode == 0:
            for executable in (path / "release/install").glob(
                "*/ubuntu/24.04/x86_64/*/bin/check-install"
            ):
                if not executable.stat().st_mode & stat.S_IXUSR:
                    errors.append("executable mode was not restored")
        for message in log_contains:
            if message not in process.stdout:
                errors.append("missing log: " + message)
        for message in log_excludes:
            if message in process.stdout:
                errors.append("unexpected log: " + message)
        if preserve and (
            self.tree(path) != previous
            or self.inventory(path) != inventory
            or self.contents(path) != contents
        ):
            errors.append("previous tree changed")
        if reused_archive:
            payloads = lambda files: {
                name: fingerprint
                for name, fingerprint in files.items()
                if not name.endswith("/ota-install.json")
            }
            if payloads(self.contents(path)) != payloads(contents):
                errors.append("reused payload changed")
            if self.contents(path, base=Path(previous)) != contents:
                errors.append("retained generation changed during metadata refresh")
            for name in packages:
                metadata_path = (
                    path
                    / "release/install"
                    / name
                    / "ubuntu/24.04/x86_64/release/ota-install.json"
                )
                metadata = (
                    json.loads(metadata_path.read_text())
                    if metadata_path.exists()
                    else {}
                )
                if metadata.get("archiveId") != reused_archive:
                    errors.append("archive reference not refreshed: " + name)
        self.results.append(
            {
                "case": label,
                "passed": not errors,
                "errors": errors,
                "exit": process.returncode,
                "seconds": round(time.monotonic() - started, 3),
                "packages": self.inventory(path),
                "log": label + ".log",
            }
        )
        print(
            ("PASS" if not errors else "FAIL")
            + " "
            + label
            + (": " + "; ".join(errors) if errors else ""),
            flush=True,
        )
        return process.stdout

    def verify(self):
        n = self.names
        closure = lambda root, version: {
            n[label]: version for label in (root, "core", "leaf")
        }
        gui = self.workspace("single-gui")
        self.source(gui, "test_plugin", dependencies=[n["missing"]])
        self.run("single-gui", gui, [n["gui"]], packages=closure("gui", "1.0.0"))
        raibo = self.workspace("single-raibo2")
        self.run(
            "single-raibo2", raibo, [n["raibo2"]], packages=closure("raibo2", "1.0.0")
        )
        # Remove the unrelated source before reusing this baseline.
        shutil.rmtree(gui / "src")
        baseline = self.workspace("baseline", clone=gui)
        self.run(
            "warm-reuse",
            gui,
            [n["gui"]],
            packages=closure("gui", "1.0.0"),
            select_archive=False,
            preserve=True,
            log_contains=("OTA lookup skipped",),
        )
        multiple = self.workspace("multiple-targets")
        self.run(
            "multiple-targets",
            multiple,
            [n["gui"], n["raibo2"]],
            packages={n[label]: "1.0.0" for label in ("gui", "raibo2", "core", "leaf")},
        )
        self.run(
            "upgrade-latest",
            gui,
            [n["gui"], "--upgrade"],
            packages=closure("gui", "2.0.0"),
        )
        self.run(
            "upgrade-unchanged",
            gui,
            [n["gui"], "--upgrade"],
            preserve=True,
            log_contains=("already matches",),
        )
        self.set_tag("latest", self.archives["same-content"])
        self.run(
            "upgrade-identical-content-new-archive",
            gui,
            [n["gui"], "--upgrade"],
            packages=closure("gui", "2.0.0"),
            log_contains=("Prepared archive metadata", "already matches"),
            log_excludes=("Downloading",),
            reused_archive=self.archives["same-content"]["id"],
        )
        self.set_tag("latest", self.archives["2.0.0"])
        self.run(
            "upgrade-stable-keeps-newer",
            gui,
            [n["gui"], "--upgrade", "--tag", "stable"],
            packages=closure("gui", "2.0.0"),
            preserve=True,
            log_contains=("already newer",),
        )
        self.run(
            "upgrade-downgrade-rejected",
            gui,
            [n["gui"] + "<2", "--upgrade", "--tag", "stable"],
            expected=1,
            preserve=True,
            log_contains=("would downgrade",),
        )
        self.set_tag("latest", self.archives["republished"])
        self.run(
            "same-version-republished",
            gui,
            [n["gui"], "--upgrade"],
            packages=closure("gui", "2.0.0"),
            log_contains=("Downloading",),
        )
        payload = self.package_path(gui, "gui") / "payload.txt"
        if payload.exists() and "republished" not in payload.read_text():
            self.results[-1]["passed"] = False
            self.results[-1]["errors"].append("same-version payload was not replaced")
        self.set_tag("latest", self.archives["2.0.0"])
        local = self.workspace("local-source")
        source = self.source(local, "gui", "0.1.0", [n["core"] + ">=2"])
        self.run(
            "source-target-retained",
            local,
            [n["gui"] + ">=2", "--upgrade"],
            packages={n["core"]: "2.0.0", n["leaf"]: "2.0.0"},
            log_contains=("despite required",),
        )
        self.run(
            "source-version-strict",
            local,
            [n["gui"] + ">=2", "--strict-local-version"],
            expected=1,
            preserve=True,
        )
        consumer = self.workspace("unrelated-source-consumer", clone=baseline)
        self.source(consumer, "other_consumer", dependencies=[n["core"] + "<2"])
        self.run(
            "unrelated-source-consumer-allowed",
            consumer,
            [n["gui"], "--upgrade"],
            packages=closure("gui", "2.0.0"),
        )
        selected_consumer = self.workspace("selected-source-consumer", clone=baseline)
        self.source(
            selected_consumer, "other_consumer", dependencies=[n["core"] + "<2"]
        )
        self.run(
            "selected-source-consumer-conflict",
            selected_consumer,
            [n["gui"], "--upgrade", "--include-local"],
            expected=1,
            preserve=True,
        )
        self.run(
            "bare-source-roots",
            local,
            [],
            packages={n["core"]: "2.0.0", n["leaf"]: "2.0.0"},
            expected=1,
            preserve=True,
        )  # Stable cannot satisfy the source's >=2 requirement.
        self.run(
            "bare-source-upgrade",
            local,
            ["--upgrade"],
            packages={n["core"]: "2.0.0", n["leaf"]: "2.0.0"},
        )
        source.rename(local / "gui-source-outside-src")
        self.run(
            "moved-source-downloads-binary",
            local,
            [n["gui"], "--upgrade"],
            packages=closure("gui", "2.0.0"),
        )
        include = self.workspace("include-local")
        self.source(include, "test_plugin", dependencies=[n["missing"]])
        self.run(
            "include-local-failure",
            include,
            [n["gui"], "--include-local"],
            expected=1,
            preserve=True,
        )
        empty = self.workspace("empty")
        self.run(
            "bare-empty-requires-all",
            empty,
            [],
            expected=1,
            preserve=True,
            select_archive=False,
            log_contains=("raisin install --all",),
        )
        all_path = self.workspace("all", clone=baseline)
        self.source(all_path, "raibo2")
        self.run(
            "all-local-priority",
            all_path,
            ["--all", "--upgrade"],
            packages={n[label]: "2.0.0" for label in ("gui", "core", "leaf", "extra")},
        )
        self.run(
            "all-unchanged",
            all_path,
            ["--all", "--upgrade"],
            preserve=True,
            log_contains=("already matches",),
        )
        self.set_tag("latest", self.archives["same-content"])
        self.run(
            "all-identical-content-new-archive",
            all_path,
            ["--all", "--upgrade"],
            packages={n[label]: "2.0.0" for label in ("gui", "core", "leaf", "extra")},
            log_contains=("Prepared archive metadata", "already matches"),
            log_excludes=("Downloading",),
            reused_archive=self.archives["same-content"]["id"],
        )
        self.set_tag("latest", self.archives["2.0.0"])
        self.source(all_path, "test_plugin", dependencies=[n["missing"]])
        self.run(
            "all-include-local-failure",
            all_path,
            ["--all", "--upgrade", "--include-local"],
            expected=1,
            preserve=True,
        )
        for variant in (
            "missing-dependency",
            "constraint-conflict",
            "bad-yaml",
            "version-mismatch",
        ):
            path = self.workspace(variant, clone=baseline)
            self.run(
                variant,
                path,
                [n["gui"], "--archive-version", variant],
                expected=1,
                preserve=True,
            )
            self.run(
                "all-" + variant,
                path,
                ["--all", "--archive-version", variant],
                expected=1,
                preserve=True,
            )
        versionless = self.workspace("versionless")
        self.run(
            "versionless-single",
            versionless,
            [n["gui"], "--archive-version", "versionless"],
            packages=closure("gui", "2.0.0"),
        )
        self.run(
            "versionless-all",
            versionless,
            ["--all", "--archive-version", "versionless"],
            packages={
                n[label]: "2.0.0"
                for label in ("gui", "raibo2", "core", "leaf", "extra")
            },
        )
        self.set_tag("latest", self.archives["versionless"])
        self.run(
            "versionless-unchanged",
            versionless,
            ["--all", "--upgrade"],
            preserve=True,
            log_contains=("already matches",),
        )
        self.set_tag("latest", self.archives["2.0.0"])
        time_path = self.workspace("timestamp")
        self.run(
            "timestamp-zip-version",
            time_path,
            [n["raibo2"], "--at", self.timestamp],
            packages=closure("raibo2", "2.0.0"),
            select_archive=False,
        )
        fallback = self.workspace("fallback")
        self.run(
            "missing-tag-stable-fallback",
            fallback,
            [n["gui"], "--tag", "not-a-tag"],
            packages=closure("gui", "1.0.0"),
            log_contains=("fallback",),
        )
        self.run(
            "legacy-latest-by-time",
            fallback,
            [
                n["gui"],
                "--tag",
                "none",
                "--archive-name",
                self.prefix + "-debug",
                "--type",
                "debug",
            ],
            select_archive=False,
        )
        if self.inventory(fallback, "debug") != {n["gui"]: "2.0.0"}:
            self.results[-1]["passed"] = False
            self.results[-1]["errors"].append(
                "latest-by-time debug package was not installed"
            )
        debug = self.workspace("debug")
        self.run(
            "debug-archive",
            debug,
            [n["gui"], "--type", "debug", "--archive-version", "debug"],
        )
        if self.inventory(debug, "debug") != {n["gui"]: "2.0.0"}:
            self.results[-1]["passed"] = False
            self.results[-1]["errors"].append("debug package was not installed")
        for label, arguments in (
            ("invalid-all-target", ["--all", n["gui"]]),
            (
                "invalid-upgrade-pin",
                [n["gui"], "--upgrade", "--archive-version", "1.0.0"],
            ),
            ("missing-package", [n["missing"]]),
            ("missing-archive", [n["gui"], "--archive-version", "does-not-exist"]),
        ):
            self.run(label, empty, arguments, expected=1, preserve=True)

    def cleanup(self):
        failures = []
        for kind in ("archive-tags", "archives", "manifests", "packages"):
            for identifier in reversed(self.resources[kind]):
                try:
                    self.api("DELETE", f"/{kind}/{identifier}")
                except Exception as error:
                    failures.append(str(error))
        return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8001/api")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if urlsplit(args.endpoint).hostname not in ("127.0.0.1", "::1"):
        parser.error(
            "this fixture publisher runs only against a literal loopback server"
        )
    output = args.output or Path(tempfile.mkdtemp(prefix="raisin-install-live-"))
    verification = Verification(args.endpoint, output)
    error = None
    try:
        verification.fixtures()
        verification.verify()
    except Exception as exception:
        error = str(exception)
        print("ERROR " + error, flush=True)
    finally:
        cleanup_errors = verification.cleanup()
        report = {
            "prefix": verification.prefix,
            "endpoint": args.endpoint,
            "results": verification.results,
            "error": error,
            "cleanup_errors": cleanup_errors,
        }
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    passed = sum(result["passed"] for result in verification.results)
    print(
        f"{passed}/{len(verification.results)} passed; report: {output / 'report.json'}"
    )
    if cleanup_errors:
        print("Cleanup errors: " + "; ".join(cleanup_errors))
    return int(bool(error or cleanup_errors or passed != len(verification.results)))


if __name__ == "__main__":
    sys.exit(main())
