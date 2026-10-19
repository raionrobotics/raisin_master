"""Strict selection is opt-in; use actual resolver/transport/tree operations."""

from types import SimpleNamespace

import pytest

from raisin_ota import client as ota
from test_transaction_download_cache import archive_lab


@pytest.fixture
def assigned(archive_lab, monkeypatch):
    lab = archive_lab
    lab.target = dict(
        name="desired-robot",
        version="2026.10.19",
        archiveId="archive-id",
        platform=lab.context.platform,
        packages=lab.packages,
    )
    lab.state = dict(reason="assigned", target=lab.target)
    lab.unauthorized = False
    monkeypatch.setattr(
        ota,
        "fetch_robot_desired_state",
        lambda: SimpleNamespace(
            unauthorized=lab.unauthorized,
            value=lab.state,
            status=403,
            detail="fixture refusal",
        ),
    )

    def forbidden(*args, **kwargs):
        pytest.fail("desired-only selection reached a legacy archive lookup")

    monkeypatch.setattr(ota, "_fetch_archive_manifest", forbidden)
    monkeypatch.setattr(ota, "_fetch_archive_with_stable_fallback", forbidden)
    return lab


def run(lab, **options):
    with ota.PackageInstallTransaction(
        lab.install, download_cache_dir=lab.cache
    ) as transaction:
        arguments = dict(tag=None, report_snapshot=False, transaction=transaction)
        arguments.update(options)
        results = ota.download_all_from_archive("release", lab.install, **arguments)
        if results:
            assert transaction.archive_prepared and not transaction.committed
            assert set(results) == {"primary", "library"}
        return results


def test_required_desired_manifest_prepares_every_package_without_legacy_lookup(
    assigned,
):
    assert set(run(assigned, require_desired_state=True)) == {"primary", "library"}
    assert len(assigned.requests) == 2
    assert not (assigned.workspace / "install").exists()


@pytest.mark.parametrize(
    "damage",
    [
        "empty",
        "unassigned",
        "unconfigured",
        "unresolved",
        "packages-missing",
        "id-missing",
        "platform",
        "unauthorized",
    ],
)
def test_required_desired_refuses_unusable_or_missing_manifest(assigned, damage):
    if damage == "empty":
        assigned.state = None
    elif damage == "unassigned":
        assigned.state = dict(reason="no_target")
    elif damage == "unconfigured":
        assigned.state = dict(reason="unconfigured")
    elif damage == "unresolved":
        assigned.state = dict(reason="target_unresolved")
    elif damage == "packages-missing":
        assigned.target.pop("packages")
    elif damage == "id-missing":
        assigned.target.pop("archiveId")
    elif damage == "platform":
        assigned.target["platform"] = "ubuntu-24.04-arm64"
    elif damage == "unauthorized":
        assigned.unauthorized = True
    with pytest.raises(ota.OtaDesiredStateUnusable):
        run(assigned, require_desired_state=True)
    assert not assigned.requests


def test_required_desired_preserves_halt_exception(assigned):
    assigned.state = dict(halt=True, haltSources=["fleet"])
    with pytest.raises(ota.OtaInstallHalted):
        run(assigned, require_desired_state=True)
    assert not assigned.requests


def test_required_selection_keeps_package_preparation_failure_result(assigned):
    assigned.target["packages"] = [None]
    assert run(assigned, require_desired_state=True) == {}
    assert not assigned.requests


@pytest.mark.parametrize("pin", ["name", "version", "env", "whitespace-env"])
def test_required_desired_rejects_pins_before_tree_repair(assigned, monkeypatch, pin):
    arguments = dict(require_desired_state=True)
    if pin == "name":
        arguments["archive_name"] = "operator-pin"
    elif pin == "version":
        arguments["archive_version"] = "2026.1"
    else:
        monkeypatch.setenv(
            "RAISIN_ARCHIVE_NAME", " " if pin == "whitespace-env" else "operator-pin"
        )

    def forbidden(*args):
        pytest.fail("pin refusal occurred after tree repair")

    monkeypatch.setattr(ota.install_tree, "ensure_tree", forbidden)
    with pytest.raises(ValueError):
        run(assigned, **arguments)
    assert not assigned.requests and not assigned.install.parent.exists()


@pytest.mark.parametrize("value", [None, 1, "true"])
def test_desired_requirement_flag_must_be_boolean(assigned, value):
    with pytest.raises(ValueError):
        run(assigned, require_desired_state=value)
    assert not assigned.install.parent.exists()


@pytest.mark.parametrize("options", [{}, {"require_desired_state": False}])
def test_omission_and_false_preserve_legacy_latest_without_assignment(
    assigned, monkeypatch, options
):
    assigned.state = None
    lookups = []

    def legacy(name, platform, version):
        lookups.append((name, platform, version))
        return assigned.packages, "archive-id", "2026.10.19"

    monkeypatch.setattr(ota, "_fetch_archive_manifest", legacy)
    assert run(assigned, **options)
    assert lookups == [("raisin-robot", assigned.context.platform, None)]


def test_default_mode_keeps_operator_pin_and_skips_desired_resolution(
    assigned, monkeypatch
):
    monkeypatch.setenv("RAISIN_ARCHIVE_NAME", "operator-pin")

    def forbidden():
        pytest.fail("legacy operator pin unexpectedly resolved desired state")

    monkeypatch.setattr(ota, "fetch_robot_desired_state", forbidden)
    monkeypatch.setattr(
        ota,
        "_fetch_archive_manifest",
        lambda *args: (assigned.packages, "archive-id", "2026.10.19"),
    )
    assert run(assigned)
