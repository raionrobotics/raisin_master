"""Single-package installs through the OTA selector and real ZIP extraction.

Only archive lookup and blob transfer are replaced. Package manifests, source
selection, version constraints, install-tree preparation and extraction run in
temporary workspaces.
"""

from pathlib import Path
from types import SimpleNamespace
import json
import zipfile

import pytest
import yaml
from click.testing import CliRunner

from commands import globals as g
from commands import install
from raisin_ota import client as ota
from raisin_ota import install_tree


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    for key, value in {
        "script_directory": str(tmp_path),
        "os_type": "ubuntu",
        "os_version": "24.04",
        "architecture": "x86_64",
    }.items():
        monkeypatch.setattr(g, key, value)
    monkeypatch.delenv("RAISIN_ARCHIVE_NAME", raising=False)
    monkeypatch.setattr(
        ota,
        "_context",
        ota.OtaContext(
            tmp_path,
            "ubuntu",
            "24.04",
            "x86_64",
        ),
    )
    monkeypatch.setattr(install, "load_configuration", lambda: ({}, "user", [], []))
    monkeypatch.setattr(ota, "get_install_session_id", lambda: "test-install")
    monkeypatch.setattr(ota, "record_install_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(ota, "_queue_snapshot_report", lambda **kwargs: None)
    monkeypatch.setattr(
        ota, "_resolve_desired_state", lambda platform: (False, None, None, None)
    )

    remote = {}
    lookups = []
    transfers = []

    def package_dir(name):
        return tmp_path / "release/install" / name / "ubuntu/24.04/x86_64/release"

    def write_manifest(directory, version, dependencies=()):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "release.yaml").write_text(
            yaml.safe_dump(
                {
                    "version": version,
                    "dependencies": list(dependencies),
                }
            ),
            encoding="utf-8",
        )
        return directory

    def source(name, version="1.0.0", dependencies=()):
        return write_manifest(tmp_path / "src" / name, version, dependencies)

    def installed(name, version="1.0.0", dependencies=()):
        return write_manifest(package_dir(name), version, dependencies)

    def publish(
        name, version="1.0.0", dependencies=(), *, blob_hash=None, manifest_hash=None
    ):
        remote[name] = {
            "version": version,
            "dependencies": list(dependencies),
            "blobHash": blob_hash,
            "manifestHash": manifest_hash,
        }

    def manifest(*args):
        lookups.append(args)
        return (
            [
                {
                    "packageName": name,
                    "packageId": name,
                    "tagName": f"v{info['version']}",
                    "blobHash": info.get("blobHash"),
                    "manifestHash": info.get("manifestHash"),
                }
                for name, info in remote.items()
            ],
            "archive-id",
            "1.0.0",
        )

    def transfer(archive_id, package_id, name, download_path, **kwargs):
        transfers.append(name)
        download_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(download_path, "w") as archive:
            archive.writestr("release.yaml", yaml.safe_dump(remote[name]))
            archive.writestr("payload.txt", f"{name}=={remote[name]['version']}")
        return True, None

    monkeypatch.setattr(ota, "_fetch_archive_with_stable_fallback", manifest)
    monkeypatch.setattr(ota, "_fetch_archive_manifest", manifest)
    monkeypatch.setattr(ota, "_download_package_blob", transfer)
    return SimpleNamespace(
        root=tmp_path,
        source=source,
        installed=installed,
        publish=publish,
        package_dir=package_dir,
        lookups=lookups,
        transfers=transfers,
    )


@pytest.mark.parametrize("target", ["raisin_raibo2", "raisin_gui"])
def test_single_target_extracts_all_dependencies_and_ignores_unrelated_source(
    workspace, target
):
    workspace.source("test_plugin", dependencies=["unpublished_dependency"])
    workspace.publish(target, dependencies=["raisin>=0.3.9", "robot_packages"])
    workspace.publish("raisin", "0.3.10", ["common>=0.1.2"])
    workspace.publish(
        "robot_packages", dependencies=["common>=0.1.2", "robot_libraries"]
    )
    workspace.publish("common", "0.1.2")
    workspace.publish("robot_libraries")

    assert install.install_command([target], "release")

    assert set(workspace.transfers) == {
        target,
        "raisin",
        "robot_packages",
        "common",
        "robot_libraries",
    }
    assert len(workspace.transfers) == 5
    for name in workspace.transfers:
        assert (workspace.package_dir(name) / "payload.txt").is_file()
    assert not workspace.package_dir("test_plugin").exists()


def test_include_local_adds_source_dependencies_to_an_explicit_target(
    workspace, capsys
):
    workspace.source("test_plugin", dependencies=["plugin_library>=1.0.0"])
    workspace.publish("raisin_gui", dependencies=["raisin>=0.3.9"])
    workspace.publish("raisin", "0.3.10")
    workspace.publish("plugin_library")

    assert install.install_command(["raisin_gui"], "release", include_local=True)

    assert set(workspace.transfers) == {"raisin_gui", "raisin", "plugin_library"}
    assert "test_plugin==1.0.0" in capsys.readouterr().out


def test_include_local_and_explicit_tag_keep_active_source_targets(workspace):
    workspace.source("raisin_gui", "0.2.7")
    workspace.source("test_plugin", dependencies=["plugin_library"])
    workspace.publish("raisin_gui", "0.2.8")
    workspace.publish("plugin_library")

    assert install.install_command(
        ["raisin_gui"], "release", tag="latest", include_local=True
    )
    assert workspace.transfers == ["plugin_library"]
    assert not workspace.package_dir("raisin_gui").exists()


@pytest.mark.parametrize("tag", [None, "latest"])
def test_include_local_without_targets_reads_source_roots_and_their_dependencies(
    workspace, tag
):
    workspace.source("test_plugin", dependencies=["raisin>=0.3.9"])
    # An old installed root must not hide dependencies of the active source.
    workspace.installed("test_plugin", dependencies=[])
    workspace.publish("raisin", "0.3.10")

    assert install.install_command([], "release", tag=tag, include_local=True)

    assert workspace.transfers == ["raisin"]


def test_bare_install_without_sources_requires_explicit_all(
    workspace, monkeypatch, capsys
):
    calls = []

    def download_all(*args, **kwargs):
        calls.append(kwargs)
        return {"raisin": {"version": "0.3.10"}}

    monkeypatch.setattr(install, "download_all_from_archive", download_all)

    assert not install.install_command([], "release")
    assert not calls
    assert "raisin install --all" in capsys.readouterr().out
    assert workspace.transfers == []


def test_bare_install_resolves_local_source_dependencies(workspace, monkeypatch):
    workspace.source("test_plugin", dependencies=["raisin>=0.3.9"])
    workspace.publish("raisin", "0.3.10")
    monkeypatch.setattr(
        install,
        "download_all_from_archive",
        lambda *a, **kw: pytest.fail("source roots must not install the archive"),
    )

    assert install.install_command([], "release")
    assert workspace.transfers == ["raisin"]


def test_include_local_without_targets_or_source_does_not_install_whole_archive(
    workspace, monkeypatch, capsys
):
    def unexpected_archive(*args, **kwargs):
        pytest.fail("An empty source-only request must not install the whole archive")

    monkeypatch.setattr(install, "download_all_from_archive", unexpected_archive)

    assert not install.install_command([], "release", include_local=True)
    assert "no local source packages found" in capsys.readouterr().out


def test_cli_include_local_installs_requested_and_source_dependencies(
    workspace, monkeypatch
):
    workspace.source("test_plugin", dependencies=["plugin_library"])
    workspace.publish("raisin_gui")
    workspace.publish("plugin_library")
    for name in (
        "flush_pending_snapshot_reports",
        "report_install_outcome",
        "flush_install_events",
        "clear_install_session",
    ):
        monkeypatch.setattr(install, name, lambda *args, **kwargs: None)

    result = CliRunner().invoke(
        install.install_cli_command, ["raisin_gui", "--include-local"]
    )

    assert result.exit_code == 0, result.output
    assert workspace.transfers == ["raisin_gui", "plugin_library"]


@pytest.mark.parametrize("kind", ["source", "installed"])
def test_compatible_local_dependency_is_logged_and_its_dependencies_are_resolved(
    workspace, capsys, kind
):
    directory = getattr(workspace, kind)("raisin", "0.3.10", ["common>=0.1.2"])
    workspace.publish("raisin_gui", dependencies=["raisin>=0.3.9"])
    workspace.publish("common", "0.1.2")

    assert install.install_command(["raisin_gui"], "release")

    assert workspace.transfers == ["raisin_gui", "common"]
    output = capsys.readouterr().out
    assert "raisin==0.3.10" in output
    assert str(directory.resolve()) in output
    assert "OTA lookup skipped" in output


def test_incompatible_installed_dependency_is_replaced_from_ota(workspace, capsys):
    workspace.installed("raisin", "0.3.6")
    workspace.publish("raisin_gui", dependencies=["raisin>=0.3.9"])
    workspace.publish("raisin", "0.3.10")

    assert install.install_command(["raisin_gui"], "release")

    assert workspace.transfers == ["raisin_gui", "raisin"]
    assert "0.3.10" in (workspace.package_dir("raisin") / "payload.txt").read_text()
    assert "does not satisfy '>=0.3.9'. Checking OTA" in capsys.readouterr().out


def test_strict_local_version_fails_instead_of_hiding_source_with_a_binary(
    workspace, capsys
):
    workspace.source("raisin", "0.3.6")
    workspace.publish("raisin_gui", dependencies=["raisin>=0.3.9"])
    workspace.publish("raisin", "0.3.10")

    assert not install.install_command(
        ["raisin_gui"], "release", strict_local_version=True
    )

    output = capsys.readouterr().out
    assert "0.3.6" in output
    assert "Local source 'raisin' cannot satisfy '>=0.3.9'" in output
    assert "repos_to_ignore" in output
    assert workspace.transfers == ["raisin_gui"]
    assert not workspace.package_dir("raisin_gui").exists()
    assert "Installation process finished with errors" in output
    assert "finished successfully" not in output


@pytest.mark.parametrize("source_version", ["0.3.6", None, "working-tree"])
def test_default_keeps_mismatched_source_and_installs_all_other_dependencies(
    workspace, capsys, source_version
):
    source = workspace.source("raisin", source_version, ["source_helper"])
    manifest_before = (source / "release.yaml").read_bytes()
    workspace.publish("raisin_gui", dependencies=["raisin>=0.3.9", "gui_helper"])
    workspace.publish("raisin", "0.3.10", ["binary_only_helper"])
    workspace.publish("source_helper")
    workspace.publish("gui_helper")

    assert install.install_command(["raisin_gui"], "release", tag="latest")

    assert workspace.transfers == ["raisin_gui", "gui_helper", "source_helper"]
    assert not workspace.package_dir("raisin").exists()
    assert (source / "release.yaml").read_bytes() == manifest_before
    output = capsys.readouterr().out
    assert "Local source version warnings (sources retained for build)" in output
    assert str(source) in output
    assert "required '>=0.3.9'" in output
    assert "These source versions have not been verified" in output


def test_local_version_warning_does_not_hide_other_dependency_failures(
    workspace, capsys
):
    previous = prepare_previous_tree(workspace)
    workspace.source("raisin", "0.3.6", ["missing_source_dependency"])
    workspace.publish("gui", "2.0.0", ["raisin>=0.3.9", "available_dependency"])
    workspace.publish("available_dependency")

    assert not install.install_command(["gui"], "release", tag="latest")

    assert workspace.transfers == ["gui", "available_dependency"]
    assert (workspace.root / "release/install").resolve() == previous
    assert not workspace.package_dir("available_dependency").exists()
    output = capsys.readouterr().out
    assert "Could not resolve 'missing_source_dependency'" in output
    assert "Local source version warnings" in output


def test_local_version_warning_does_not_ignore_binary_version_constraints(
    workspace, capsys
):
    workspace.source("raisin_gui", "0.2.7", ["shared>=2"])
    workspace.publish("shared", "1.0.0")

    assert not install.install_command(["raisin_gui>=0.3"], "release")
    assert not workspace.transfers
    assert "Could not resolve 'shared' (required: '>=2')" in capsys.readouterr().out


@pytest.mark.parametrize("strict", [False, True])
def test_cli_source_version_policy_defaults_to_warning_and_supports_strict_mode(
    workspace, monkeypatch, strict
):
    workspace.source("raisin_gui", "0.2.7", ["source_helper"])
    workspace.publish("source_helper")
    for name in (
        "flush_pending_snapshot_reports",
        "report_install_outcome",
        "flush_install_events",
        "clear_install_session",
    ):
        monkeypatch.setattr(install, name, lambda *args, **kwargs: None)
    arguments = ["raisin_gui>=0.3"]
    if strict:
        arguments.append("--strict-local-version")

    result = CliRunner().invoke(install.install_cli_command, arguments)

    assert result.exit_code == (1 if strict else 0), result.output
    if strict:
        assert not workspace.transfers
        assert "Local source 'raisin_gui' cannot satisfy '>=0.3'" in result.output
    else:
        assert workspace.transfers == ["source_helper"]
        assert "Local source version warnings" in result.output


@pytest.mark.parametrize("strict", [False, True])
def test_unversioned_source_root_does_not_hide_a_later_explicit_requirement(
    workspace, capsys, strict
):
    workspace.source("local_plugin", None)
    workspace.publish("gui", dependencies=["local_plugin>=0.0.0"])

    assert install.install_command(
        ["gui"],
        "release",
        include_local=True,
        strict_local_version=strict,
    ) == (not strict)

    output = capsys.readouterr().out
    if strict:
        assert "Local source 'local_plugin' cannot satisfy '>=0.0.0'" in output
        assert not workspace.package_dir("gui").exists()
    else:
        assert "Local source version warnings" in output
        assert "required '>=0.0.0'" in output


@pytest.mark.parametrize(
    "selection",
    [
        {"tag": "latest"},
        {"tag": "stable"},
        {"tag": "none"},
        {"archive_name": "team-archive"},
        {"archive_version": "1.0.0"},
    ],
)
def test_explicit_ota_selection_preserves_source_target_and_dependencies(
    workspace, selection
):
    workspace.installed("raisin_gui", "0.2.7")
    workspace.source("raisin_gui", "0.2.7", ["raisin>=0.3.9", "common"])
    workspace.installed("raisin", "0.3.9")
    workspace.source("raisin", "0.3.9")
    workspace.publish("raisin_gui", "0.2.8", ["raisin>=0.3.9"])
    workspace.publish("raisin", "0.3.10")
    workspace.publish("common")

    assert install.install_command(["raisin_gui"], "release", **selection)

    assert workspace.transfers == ["common"]
    assert not (workspace.package_dir("raisin_gui") / "payload.txt").exists()


def test_devel_default_latest_reuses_compatible_installed_package(
    workspace, monkeypatch
):
    monkeypatch.setattr(install, "load_configuration", lambda: ({}, "devel", [], []))
    workspace.installed("raisin_gui", "0.2.7")
    workspace.publish("raisin_gui", "0.2.8")

    assert install.install_command(["raisin_gui"], "release")
    assert workspace.transfers == []
    assert not (workspace.root / "release/versions").exists()


@pytest.mark.parametrize("manifest", [None, "[broken yaml", "- not-a-mapping\n"])
def test_unverifiable_active_source_fails_with_a_diagnostic(
    workspace, capsys, manifest
):
    source = workspace.root / "src/raisin_gui"
    source.mkdir(parents=True)
    if manifest is not None:
        (source / "release.yaml").write_text(manifest)
    workspace.publish("raisin_gui", "0.2.8", ["common"])
    workspace.publish("common")

    assert not install.install_command(["raisin_gui"], "release")
    assert workspace.transfers == []
    assert "Cannot verify local source" in capsys.readouterr().out


def test_dependency_cycle_and_duplicate_requirements_finish(workspace):
    workspace.publish("plugin", dependencies=["raisin>=0.3.9", "common"])
    workspace.publish("raisin", "0.3.10", ["common"])
    workspace.publish("common", dependencies=["plugin"])

    assert install.install_command(["plugin"], "release", tag="latest")
    assert workspace.transfers == ["plugin", "raisin", "common"]


def test_conflicting_dependency_constraints_fail_without_downgrading(workspace, capsys):
    workspace.publish("plugin", dependencies=["raisin>=0.3.9", "old_plugin"])
    workspace.publish("raisin", "0.3.10")
    workspace.publish("old_plugin", dependencies=["raisin<0.3.9"])

    assert not install.install_command(["plugin"], "release", tag="latest")
    assert workspace.transfers == ["plugin", "raisin", "old_plugin"]
    assert "required: '<0.3.9,>=0.3.9'" in capsys.readouterr().out


def test_ignored_source_does_not_satisfy_a_binary_dependency(
    workspace, monkeypatch, capsys
):
    workspace.source("raisin", "0.3.10")
    monkeypatch.setattr(
        install, "load_configuration", lambda: ({}, "user", [], ["raisin"])
    )
    workspace.publish("plugin", dependencies=["raisin>=0.3.9"])
    workspace.publish("raisin", "0.3.10")

    assert install.install_command(["plugin"], "release")
    assert workspace.transfers == ["plugin", "raisin"]
    assert "excluded by repos_to_ignore" in capsys.readouterr().out


def prepare_previous_tree(workspace):
    old = workspace.installed("gui", "1.0.0")
    (old / "payload.txt").write_text("old gui")
    untouched = workspace.installed("untouched", "1.0.0")
    (untouched / "payload.txt").write_text("keep me")
    install_tree.ensure_tree(workspace.root / "release")
    return (workspace.root / "release/install").resolve()


def test_dependency_closure_activates_once_and_preserves_previous_files(
    workspace, monkeypatch
):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0", ["shared>=2"])
    workspace.publish("shared", "2.0.0")
    transfer = ota._download_package_blob
    commit = install_tree.commit_version
    commits = []
    snapshots = []

    def observe_transfer(*args, **kwargs):
        assert (workspace.root / "release/install").resolve() == previous
        assert (workspace.package_dir("gui") / "payload.txt").read_text() == "old gui"
        assert not workspace.package_dir("shared").exists()
        return transfer(*args, **kwargs)

    def observe_commit(*args, **kwargs):
        commits.append(args)
        return commit(*args, **kwargs)

    def snapshot(**kwargs):
        assert (
            workspace.package_dir("gui") / "payload.txt"
        ).read_text() == "gui==2.0.0"
        assert (
            workspace.package_dir("shared") / "payload.txt"
        ).read_text() == "shared==2.0.0"
        snapshots.append(kwargs)

    monkeypatch.setattr(ota, "_download_package_blob", observe_transfer)
    monkeypatch.setattr(install_tree, "commit_version", observe_commit)
    monkeypatch.setattr(ota, "_queue_snapshot_report", snapshot)

    assert install.install_command(["gui"], "release", tag="latest")

    assert len(commits) == 1
    assert len(snapshots) == 1
    assert snapshots[0]["install_base_path"] == workspace.root / "release/install"
    assert (
        previous / "gui/ubuntu/24.04/x86_64/release/payload.txt"
    ).read_text() == "old gui"
    assert (workspace.package_dir("untouched") / "payload.txt").read_text() == "keep me"
    assert (workspace.root / "release/install").is_symlink()
    assert (workspace.root / "release/install").resolve() != previous
    assert install_tree.rollback(workspace.root / "release") is not None
    assert (workspace.root / "release/install").resolve() == previous
    assert (workspace.package_dir("gui") / "payload.txt").read_text() == "old gui"
    assert not workspace.package_dir("shared").exists()


def test_missing_dependency_discards_staging_and_preserves_the_live_tree(
    workspace, monkeypatch
):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0", ["missing"])
    monkeypatch.setattr(
        ota,
        "_queue_snapshot_report",
        lambda **kw: pytest.fail("a failed transaction must not queue a snapshot"),
    )

    assert not install.install_command(["gui"], "release", tag="latest")
    assert (workspace.root / "release/install").resolve() == previous
    assert (workspace.package_dir("gui") / "payload.txt").read_text() == "old gui"
    assert list((workspace.root / "release/versions").iterdir()) == [previous]


@pytest.mark.parametrize("standalone", [False, True])
def test_corrupt_zip_preserves_existing_package_in_cli_and_library(
    workspace, monkeypatch, standalone
):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0")

    def corrupt(*args, **kwargs):
        target = args[3]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"not a zip")
        return True, None

    monkeypatch.setattr(ota, "_download_package_blob", corrupt)
    if standalone:
        assert (
            ota.download_package(
                "gui", "", "release", workspace.root / "release/install"
            )
            is None
        )
    else:
        assert not install.install_command(["gui"], "release", tag="latest")
    assert (workspace.root / "release/install").resolve() == previous
    assert (workspace.package_dir("gui") / "payload.txt").read_text() == "old gui"


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        "[broken yaml",
        "- scalar\n",
        "version: 2.0.0\ndependencies: missing\n",
        "version: 9.0.0\ndependencies: []\n",
    ],
)
def test_bad_downloaded_metadata_fails_without_replacing_live_packages(
    workspace, monkeypatch, metadata
):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0")

    def malformed(*args, **kwargs):
        target = args[3]
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("payload.txt", "new gui")
            if metadata is not None:
                archive.writestr("release.yaml", metadata)
        return True, None

    monkeypatch.setattr(ota, "_download_package_blob", malformed)
    assert not install.install_command(["gui"], "release", tag="latest")
    assert (workspace.root / "release/install").resolve() == previous
    assert (workspace.package_dir("gui") / "payload.txt").read_text() == "old gui"


def test_interrupted_dependency_install_does_not_activate_partial_packages(
    workspace, monkeypatch
):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0", ["shared"])
    workspace.publish("shared", "2.0.0")
    transfer = ota._download_package_blob

    def interrupt(*args, **kwargs):
        if args[2] == "shared":
            raise KeyboardInterrupt()
        return transfer(*args, **kwargs)

    monkeypatch.setattr(ota, "_download_package_blob", interrupt)
    with pytest.raises(KeyboardInterrupt):
        install.install_command(["gui"], "release", tag="latest")
    assert (workspace.root / "release/install").resolve() == previous
    assert list((workspace.root / "release/versions").iterdir()) == [previous]


@pytest.mark.parametrize("error", [None, OSError("cannot switch symlink")])
def test_failed_commit_leaves_the_previous_tree_active(workspace, monkeypatch, error):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0")

    def fail_commit(*args, **kwargs):
        if error:
            raise error
        return None

    monkeypatch.setattr(install_tree, "commit_version", fail_commit)
    assert not install.install_command(["gui"], "release", tag="latest")
    assert (workspace.root / "release/install").resolve() == previous
    assert list((workspace.root / "release/versions").iterdir()) == [previous]


@pytest.mark.parametrize("consumer_kind", ["installed", "source"])
def test_new_dependency_cannot_break_a_retained_consumer(
    workspace, consumer_kind, capsys
):
    previous = prepare_previous_tree(workspace)
    getattr(workspace, consumer_kind)("old_plugin", "1.0.0", ["shared<2"])
    workspace.publish("gui", "2.0.0", ["shared>=2"])
    workspace.publish("shared", "2.0.0")

    assert not install.install_command(["gui"], "release", tag="latest")
    assert (
        "Retained package 'old_plugin' requires 'shared<2'" in capsys.readouterr().out
    )
    assert (workspace.root / "release/install").resolve() == previous
    assert (workspace.package_dir("gui") / "payload.txt").read_text() == "old gui"


def test_source_is_preferred_over_an_installed_binary_and_uses_its_own_dependencies(
    workspace,
):
    workspace.source("raisin_gui", "0.2.7", ["source_dep"])
    workspace.installed("raisin_gui", "0.2.8", ["binary_only_dep"])
    workspace.publish("source_dep")

    assert install.install_command(["raisin_gui"], "release")
    assert workspace.transfers == ["source_dep"]


def test_source_only_install_does_not_create_a_version_or_query_ota(workspace):
    workspace.source("raisin_gui", "0.2.7", ["raisin>=0.3.9"])
    workspace.source("raisin", "0.3.10")

    assert install.install_command(["raisin_gui"], "release", tag="latest")
    assert not workspace.lookups
    assert not (workspace.root / "release").exists()


@pytest.mark.parametrize("returned_version", ["0.5.0", "2.0.0"])
def test_timestamp_download_is_validated_before_activation(
    workspace, monkeypatch, returned_version
):
    previous = prepare_previous_tree(workspace)
    monkeypatch.setattr(ota, "_get_auth_context", lambda: ("https://ota.invalid", {}))
    monkeypatch.setattr(ota, "_fetch_package_id_by_name", lambda name: name)
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {"data": {"blobHash": "test-blob", "version": returned_version}},
    )
    monkeypatch.setattr(ota.requests, "get", lambda *a, **kw: response)

    def timestamp_blob(blob_hash, target):
        assert (workspace.root / "release/install").resolve() == previous
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr(
                "release.yaml",
                yaml.safe_dump({"version": returned_version, "dependencies": []}),
            )
            archive.writestr("payload.txt", f"gui=={returned_version}")
        return True

    monkeypatch.setattr(ota, "_download_blob_by_hash", timestamp_blob)
    success = install.install_command(["gui>=1"], "release", at_timestamp="2026-01-01")
    assert success == (returned_version == "2.0.0")
    if success:
        assert (workspace.root / "release/install").resolve() != previous
        assert (
            workspace.package_dir("gui") / "payload.txt"
        ).read_text() == "gui==2.0.0"
    else:
        assert (workspace.root / "release/install").resolve() == previous
        assert (workspace.package_dir("gui") / "payload.txt").read_text() == "old gui"


def test_bare_timestamp_does_not_silently_install_a_tagged_archive(
    workspace, monkeypatch, capsys
):
    monkeypatch.setattr(
        install,
        "download_all_from_archive",
        lambda *a, **kw: pytest.fail("a timestamp must not become a tagged archive"),
    )

    assert not install.install_command([], "release", at_timestamp="2026-01-01")
    assert "--at requires package targets" in capsys.readouterr().out


def record_archive_metadata(
    path,
    version,
    *,
    archive_id="archive-id",
    blob_hash="a" * 64,
    manifest_hash="b" * 64,
):
    (path / ota._INSTALL_METADATA_FILE).write_text(
        json.dumps(
            {
                "source": "archive",
                "archiveId": archive_id,
                "packageVersion": version,
                "blobHash": blob_hash,
                "manifestHash": manifest_hash,
                "platform": "ubuntu-24.04-x86_64",
                "buildType": "release",
            }
        )
    )


def test_upgrade_queries_latest_and_updates_the_complete_dependency_closure(workspace):
    previous = prepare_previous_tree(workspace)
    workspace.installed("shared", "1.0.0")
    workspace.publish("gui", "2.0.0", ["shared>=1"])
    workspace.publish("shared", "2.0.0", ["new_dependency"])
    workspace.publish("new_dependency")

    assert install.install_command(["gui"], "release", upgrade=True)

    assert workspace.lookups == [("raisin-robot", "ubuntu-24.04-x86_64", "latest")]
    assert workspace.transfers == ["gui", "shared", "new_dependency"]
    assert (workspace.root / "release/install").resolve() != previous
    assert (
        workspace.package_dir("shared") / "payload.txt"
    ).read_text() == "shared==2.0.0"


def test_upgrade_respects_an_explicit_channel(workspace):
    workspace.publish("gui", "2.0.0")

    assert install.install_command(["gui"], "release", upgrade=True, tag="stable")
    assert workspace.lookups[0][2] == "stable"


def test_upgrade_preserves_sources_and_updates_missing_or_installed_binary_dependencies(
    workspace, capsys
):
    source = workspace.source("gui", "1.0.0", ["shared>=2"])
    workspace.installed("shared", "1.0.0")
    workspace.publish("gui", "2.0.0", ["binary_only_dependency"])
    workspace.publish("shared", "2.0.0")

    assert install.install_command(["gui>=2"], "release", upgrade=True)

    assert workspace.transfers == ["shared"]
    assert yaml.safe_load((source / "release.yaml").read_text())["version"] == "1.0.0"
    assert "Local source version warnings" in capsys.readouterr().out


def test_upgrade_does_not_downgrade_a_newer_binary_and_still_updates_its_dependencies(
    workspace, capsys
):
    workspace.installed("gui", "3.0.0", ["shared"])
    workspace.installed("shared", "1.0.0")
    workspace.publish("gui", "2.0.0", ["wrong_dependency"])
    workspace.publish("shared", "2.0.0")

    assert install.install_command(["gui"], "release", upgrade=True)

    assert workspace.transfers == ["shared"]
    assert (
        yaml.safe_load((workspace.package_dir("gui") / "release.yaml").read_text())[
            "version"
        ]
        == "3.0.0"
    )
    assert "already newer" in capsys.readouterr().out


def test_upgrade_fails_when_constraints_would_require_a_downgrade(workspace, capsys):
    workspace.installed("gui", "3.0.0")
    workspace.publish("gui", "2.0.0")

    assert not install.install_command(["gui<3"], "release", upgrade=True)
    assert not workspace.transfers
    assert "would downgrade 3.0.0 to 2.0.0" in capsys.readouterr().out
    assert (
        yaml.safe_load((workspace.package_dir("gui") / "release.yaml").read_text())[
            "version"
        ]
        == "3.0.0"
    )


def test_upgrade_keeps_a_compatible_pinned_version_when_the_archive_has_no_matching_update(
    workspace,
):
    workspace.installed("gui", "2.0.0", ["shared"])
    workspace.publish("gui", "3.0.0")
    workspace.publish("shared", "2.0.0")

    assert install.install_command(["gui==2.0.0"], "release", upgrade=True)
    assert workspace.transfers == ["shared"]


def test_upgrade_reuses_matching_archive_and_hashes_but_resolves_its_dependencies(
    workspace,
):
    directory = workspace.installed("gui", "2.0.0", ["shared"])
    record_archive_metadata(directory, "2.0.0")
    workspace.publish(
        "gui", "2.0.0", ["shared"], blob_hash="a" * 64, manifest_hash="b" * 64
    )
    workspace.publish("shared", "2.0.0")

    assert install.install_command(["gui"], "release", upgrade=True)
    assert workspace.transfers == ["shared"]


@pytest.mark.parametrize(
    "archive_id,blob_hash,manifest_hash",
    [
        ("archive-id", "a" * 64, "b" * 64),
        ("archive-id", "c" * 64, "b" * 64),
        ("archive-id", "a" * 64, "c" * 64),
        ("older-archive", "a" * 64, "b" * 64),
        ("archive-id", None, None),
    ],
)
def test_same_version_upgrade_checks_provenance_before_skipping_download(
    workspace, archive_id, blob_hash, manifest_hash
):
    directory = workspace.installed("gui", "2.0.0")
    (directory / "payload.txt").write_text("previous build")
    record_archive_metadata(
        directory,
        "2.0.0",
        archive_id=archive_id,
        blob_hash=blob_hash,
        manifest_hash=manifest_hash,
    )
    workspace.publish("gui", "2.0.0", blob_hash="a" * 64, manifest_hash="b" * 64)

    assert install.install_command(["gui"], "release", upgrade=True)

    unchanged = (
        archive_id == "archive-id"
        and blob_hash == "a" * 64
        and manifest_hash == "b" * 64
    )
    assert workspace.transfers == ([] if unchanged else ["gui"])
    assert (directory / "payload.txt").read_text() == (
        "previous build" if unchanged else "gui==2.0.0"
    )
    if unchanged:
        assert not (workspace.root / "release/versions").exists()


def test_upgrade_failure_does_not_activate_a_partially_updated_tree(workspace):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0", ["missing_dependency"])

    assert not install.install_command(["gui"], "release", upgrade=True)
    assert (workspace.root / "release/install").resolve() == previous
    assert (workspace.package_dir("gui") / "payload.txt").read_text() == "old gui"


def test_all_uses_one_manifest_and_one_commit_without_changing_active_sources(
    workspace, monkeypatch
):
    source = workspace.source("gui", "1.0.0", ["shared>=2"])
    workspace.publish("gui", "2.0.0")
    workspace.publish("shared", "2.0.0")
    workspace.publish("extra")
    commit = install_tree.commit_version
    commits = []

    def observe_commit(*args, **kwargs):
        commits.append(args)
        return commit(*args, **kwargs)

    monkeypatch.setattr(install_tree, "commit_version", observe_commit)
    assert install.install_command([], "release", all_packages=True)
    assert set(workspace.transfers) == {"shared", "extra"}
    assert len(commits) == 1
    assert len(workspace.lookups) == 1
    assert not workspace.package_dir("gui").exists()
    assert yaml.safe_load((source / "release.yaml").read_text())["version"] == "1.0.0"


def test_all_resolves_zip_dependencies_before_commit_and_keeps_unrelated_packages(
    workspace,
):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0", ["shared>=2"])
    workspace.publish("shared", "2.0.0")

    assert install.install_command([], "release", all_packages=True)
    assert (workspace.root / "release/install").resolve() != previous
    assert (workspace.package_dir("untouched") / "payload.txt").read_text() == "keep me"
    assert workspace.transfers == ["gui", "shared"]


def test_all_missing_dependency_preserves_the_previous_tree(workspace):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0", ["missing_dependency"])

    assert not install.install_command([], "release", all_packages=True)
    assert (workspace.root / "release/install").resolve() == previous
    assert (workspace.package_dir("gui") / "payload.txt").read_text() == "old gui"


def test_all_rejects_a_binary_constraint_conflict_before_activation(workspace):
    previous = prepare_previous_tree(workspace)
    workspace.publish("gui", "2.0.0", ["shared>=2"])
    workspace.publish("shared", "1.0.0")

    assert not install.install_command([], "release", all_packages=True)
    assert (workspace.root / "release/install").resolve() == previous


def test_all_upgrade_queries_latest_and_retains_a_newer_installed_package(workspace):
    workspace.installed("gui", "3.0.0")
    workspace.publish("gui", "2.0.0")
    workspace.publish("extra")

    assert install.install_command([], "release", all_packages=True, upgrade=True)
    assert workspace.transfers == ["extra"]
    assert workspace.lookups[0][2] == "latest"
    assert (
        yaml.safe_load((workspace.package_dir("gui") / "release.yaml").read_text())[
            "version"
        ]
        == "3.0.0"
    )


@pytest.mark.parametrize("include_local", [False, True])
def test_all_adds_unrelated_sources_only_when_include_local_is_requested(
    workspace, include_local
):
    workspace.source("unrelated", dependencies=["missing_dependency"])
    workspace.publish("gui", "2.0.0")

    assert install.install_command(
        [], "release", all_packages=True, include_local=include_local
    ) == (not include_local)
    assert workspace.package_dir("gui").exists() == (not include_local)


@pytest.mark.parametrize(
    "arguments",
    [
        ["gui", "--all"],
        ["--all", "--at", "2026-01-01"],
        ["gui", "--upgrade", "--at", "2026-01-01"],
        ["gui", "--upgrade", "--archive-version", "1.0.0"],
    ],
)
def test_invalid_mode_combinations_fail_before_any_ota_lookup(
    workspace, monkeypatch, arguments
):
    for name in (
        "flush_pending_snapshot_reports",
        "report_install_outcome",
        "flush_install_events",
        "clear_install_session",
    ):
        monkeypatch.setattr(install, name, lambda *a, **kw: None)

    result = CliRunner().invoke(install.install_cli_command, arguments)

    assert result.exit_code == 1, result.output
    assert not workspace.lookups
    assert not (workspace.root / "release/install").exists()


def test_cli_all_upgrade_installs_latest_packages(workspace, monkeypatch):
    workspace.publish("gui", "2.0.0")
    for name in (
        "flush_pending_snapshot_reports",
        "report_install_outcome",
        "flush_install_events",
        "clear_install_session",
    ):
        monkeypatch.setattr(install, name, lambda *a, **kw: None)

    result = CliRunner().invoke(install.install_cli_command, ["--all", "--upgrade"])

    assert result.exit_code == 0, result.output
    assert workspace.lookups[0][2] == "latest"
    assert workspace.transfers == ["gui"]


def test_repeated_upgrades_observe_a_moved_latest_tag_and_pin_each_dependency_closure(
    workspace, monkeypatch
):
    workspace.publish("gui", "1.0.0", ["shared"])
    workspace.publish("shared", "1.0.0")
    state = {"archive_id": "archive-1"}
    requests = []
    monkeypatch.setattr(
        ota, "_get_auth_context", lambda: ("https://ota.example.test", {})
    )
    monkeypatch.setattr(
        ota, "_fetch_archive_with_stable_fallback", ota._fetch_archive_by_tag
    )

    def get(url, **kwargs):
        requests.append(url)
        if url.endswith("/archive-tags/by-name"):
            assert kwargs["params"]["tagName"] == "latest"
            data = {
                "manifests": [
                    {
                        "platform": "ubuntu-24.04-x86_64",
                        "archiveId": state["archive_id"],
                    }
                ]
            }
        else:
            data = {
                "id": state["archive_id"],
                "version": state["archive_id"],
                "packages": [
                    {"packageName": name, "packageId": name, "tagName": f"v{version}"}
                    for name, version in (
                        ("gui", state.get("version", "1.0.0")),
                        ("shared", state.get("version", "1.0.0")),
                    )
                ],
            }
        return SimpleNamespace(
            raise_for_status=lambda: None, json=lambda: {"data": data}
        )

    monkeypatch.setattr(ota.requests, "get", get)
    assert install.install_command(["gui"], "release", upgrade=True)

    state.update(archive_id="archive-2", version="2.0.0")
    workspace.publish("gui", "2.0.0", ["shared"])
    workspace.publish("shared", "2.0.0")
    assert install.install_command(["gui"], "release", upgrade=True)

    assert len(requests) == 4  # One tag + manifest request per install attempt.
    assert workspace.transfers == ["gui", "shared", "gui", "shared"]
    for name in ("gui", "shared"):
        assert (
            yaml.safe_load((workspace.package_dir(name) / "release.yaml").read_text())[
                "version"
            ]
            == "2.0.0"
        )
        metadata = json.loads(
            (workspace.package_dir(name) / "ota-install.json").read_text()
        )
        assert metadata["archiveId"] == "archive-2"


@pytest.mark.parametrize(
    "packages",
    [
        None,
        {},
        [None],
        [{"packageName": ["gui"]}],
        [{"packageName": {"name": "gui"}}],
        [{"packageName": "../gui"}],
        [{}],
    ],
)
def test_all_rejects_malformed_archive_entries_without_touching_the_live_tree(
    workspace, monkeypatch, packages
):
    previous = prepare_previous_tree(workspace)
    monkeypatch.setattr(
        ota,
        "_fetch_archive_with_stable_fallback",
        lambda *a: (packages, "archive-id", "1.0.0"),
    )

    assert not install.install_command([], "release", all_packages=True)
    assert not workspace.transfers
    assert (workspace.root / "release/install").resolve() == previous


@pytest.mark.parametrize(
    "packages", [None, [None], [{"packageName": "gui", "tagName": ["v1.0.0"]}]]
)
def test_single_package_rejects_malformed_archive_entries_without_activation(
    workspace, monkeypatch, packages
):
    previous = prepare_previous_tree(workspace)
    monkeypatch.setattr(
        ota,
        "_fetch_archive_with_stable_fallback",
        lambda *a: (packages, "archive-id", "1.0.0"),
    )

    assert not install.install_command(["gui"], "release", upgrade=True)
    assert not workspace.transfers
    assert (workspace.root / "release/install").resolve() == previous


def test_all_with_only_active_source_packages_succeeds_without_creating_a_version(
    workspace,
):
    workspace.source("gui")
    workspace.publish("gui", "2.0.0")

    assert install.install_command([], "release", all_packages=True, upgrade=True)
    assert not workspace.transfers
    assert not (workspace.root / "release/versions").exists()
