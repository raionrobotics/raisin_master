"""Real archive transactions/transport with only HTTP and reporting replaced."""

import hashlib
import io
from types import SimpleNamespace
from unittest.mock import MagicMock
import zipfile

import pytest
import requests

from raisin_ota import client as ota


@pytest.fixture
def archive_lab(tmp_path, monkeypatch):
    workspace = tmp_path / "runtime"
    context = ota.OtaContext(workspace, "ubuntu", "24.04", "x86_64")
    monkeypatch.setattr(ota, "_context", context)
    monkeypatch.setattr(ota, "_archive_cache", {})
    monkeypatch.setattr(ota, "_pending_install_failure", None)
    monkeypatch.delenv("RAISIN_ARCHIVE_NAME", raising=False)
    monkeypatch.setattr(ota, "get_install_session_id", lambda: "cache-test-session")
    monkeypatch.setattr(ota, "record_install_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(ota, "get_ota_endpoint", lambda: "https://ota.invalid")
    sessions = []

    def robot_headers(session):
        sessions.append(session)
        return {"X-Test-Node": "fixture"}

    monkeypatch.setattr(ota, "_robot_auth_headers", robot_headers)
    monkeypatch.setattr(ota.time, "sleep", lambda seconds: None)
    bodies = {}
    for name in ("primary", "library"):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("release.yaml", "version: 1.0.0\ndependencies: []\n")
            archive.writestr("payload.txt", name)
        bodies[name] = buffer.getvalue()
    packages = [
        {"packageName": name, "packageId": name, "tagName": "1.0.0"} for name in bodies
    ]
    manifest = (packages, "archive-id", "2026.10.19")
    monkeypatch.setattr(ota, "_fetch_archive_manifest", lambda *args: manifest)
    requests_seen = []
    lab = SimpleNamespace(
        workspace=workspace,
        context=context,
        install=tmp_path / "private/release/install",
        cache=tmp_path / "private/downloads",
        packages=packages,
        bodies=bodies,
        requests=requests_seen,
        sessions=sessions,
        artifacts=[],
        interrupted=False,
        partial_written=False,
    )

    def get(url, *, headers, **kwargs):
        name = url.split("/packages/", 1)[1].split("/", 1)[0]
        body = bodies[name]
        requests_seen.append((name, headers.copy()))
        if lab.interrupted and lab.partial_written:
            raise requests.ConnectionError("fixture offline")
        offset = int(headers.get("Range", "bytes=0-")[6:-1])
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 206 if offset else 200
        response.headers = {
            "X-Content-Hash": hashlib.sha256(body).hexdigest(),
            "Content-Length": str(len(body) - offset),
            "Content-Range": f"bytes {offset}-{len(body) - 1}/{len(body)}",
        }

        def chunks(**kwargs):
            if lab.interrupted:
                lab.partial_written = True
                yield body[:31]
                raise requests.ConnectionError("fixture interrupted")
            yield body[offset:]
            lab.artifacts.extend(tmp_path.rglob("*-ota-*.zip*"))

        response.iter_content.side_effect = chunks
        return response

    monkeypatch.setattr(ota.requests, "get", get)
    return lab


def prepare(lab, **options):
    return ota.PackageInstallTransaction(lab.install, **options)


def download(lab, transaction):
    return ota.download_all_from_archive(
        "release",
        lab.install,
        archive_version="2026.10.19",
        archive_name="test-robot",
        transaction=transaction,
    )


@pytest.mark.parametrize("tag", ["1.0.0", "latest", None])
def test_explicit_cache_covers_archive_and_zip_version_prefetch(archive_lab, tag):
    lab = archive_lab
    for package in lab.packages:
        package["tagName"] = tag
    with prepare(lab, download_cache_dir=lab.cache) as transaction:
        assert not lab.cache.exists()  # No eager filesystem preparation.
        result = download(lab, transaction)
        assert set(result) == {"primary", "library"}
        assert transaction.archive_prepared
        assert not transaction.committed
        for name in result:
            directory = lab.context.package_dir(
                transaction.package_base, name, "release"
            )
            assert (directory / "payload.txt").read_text() == name
        assert list(lab.cache.iterdir()) == []  # ZIPs consumed after extraction.
        assert not (lab.workspace / "install").exists()
        assert ota._ctx() is lab.context
        assert lab.sessions == ["cache-test-session"] * 2
        assert len(lab.requests) == 2
        assert len(lab.artifacts) == 4  # Each part body and its hash state.
        assert all(path.parent == lab.cache for path in lab.artifacts)
    assert not lab.install.exists()  # Preparation did not activate a generation.


@pytest.mark.parametrize("options", [{}, {"download_cache_dir": None}])
def test_omitted_or_none_cache_keeps_legacy_workspace_destination(archive_lab, options):
    lab = archive_lab
    with prepare(lab, **options) as transaction:
        assert set(download(lab, transaction)) == {"primary", "library"}
        assert (lab.workspace / "install").is_dir()
        assert all(path.parent == lab.workspace / "install" for path in lab.artifacts)
        assert not lab.cache.exists()


def test_interrupted_partial_and_resume_state_stay_in_explicit_cache(archive_lab):
    lab = archive_lab
    lab.interrupted = True
    with prepare(lab, download_cache_dir=lab.cache) as transaction:
        assert download(lab, transaction) == {}
    partial = lab.cache / "library-ota-1.0.0.zip.part"
    state = partial.with_name(partial.name + ".json")
    assert partial.stat().st_size == 31
    assert state.is_file()
    assert not (lab.workspace / "install").exists()
    lab.interrupted = False
    with prepare(lab, download_cache_dir=lab.cache) as transaction:
        assert set(download(lab, transaction)) == {"primary", "library"}
    resumed = lab.requests[-2][1]
    assert resumed["Range"] == "bytes=31-"
    assert "If-Range" in resumed
    assert not partial.exists()
    assert not state.exists()
    assert not (lab.workspace / "install").exists()


def test_explicit_unusable_cache_does_not_fall_back(archive_lab):
    lab = archive_lab
    lab.cache.parent.mkdir(parents=True)
    lab.cache.write_text("not a directory")
    with prepare(lab, download_cache_dir=lab.cache) as transaction:
        assert download(lab, transaction) == {}
    assert lab.cache.read_text() == "not a directory"
    assert not lab.requests
    assert not (lab.workspace / "install").exists()


def test_constructor_does_not_require_configured_context(tmp_path, monkeypatch):
    def unconfigured():
        pytest.fail("constructor eagerly accessed the OTA context")

    monkeypatch.setattr(ota, "_ctx", unconfigured)
    ota.PackageInstallTransaction(tmp_path / "release/install")
    ota.PackageInstallTransaction(
        tmp_path / "release/install", download_cache_dir=tmp_path / "cache"
    )


def test_explicit_zip_path_neither_accesses_context_nor_creates_cache(
    tmp_path, monkeypatch
):
    def unconfigured():
        pytest.fail("explicit cache lookup accessed the OTA context")

    monkeypatch.setattr(ota, "_ctx", unconfigured)
    cache = tmp_path / "private/cache"
    assert ota._ota_zip_path(cache, "fixture", "1.0.0") == (
        cache / "fixture-ota-1.0.0.zip"
    )
    assert not cache.exists()


def test_default_zip_path_uses_workspace_without_creating_cache(archive_lab):
    lab = archive_lab
    assert ota._ota_zip_path(None, "fixture", "1.0.0") == (
        lab.workspace / "install/fixture-ota-1.0.0.zip"
    )
    assert not lab.workspace.exists()


def test_nontransactional_archive_keeps_workspace_cache(archive_lab):
    lab = archive_lab
    result = ota.download_all_from_archive(
        "release",
        lab.install,
        archive_version="2026.10.19",
        archive_name="test-robot",
        report_snapshot=False,
    )
    assert set(result) == {"primary", "library"}
    assert lab.install.is_symlink()
    assert not lab.cache.exists()
    assert len(lab.artifacts) == 4
    assert all(path.parent == lab.workspace / "install" for path in lab.artifacts)


@pytest.fixture
def timestamp_lab(archive_lab, monkeypatch):
    lab = archive_lab
    base = "https://ota.invalid"
    digest = hashlib.sha256(lab.bodies["primary"]).hexdigest()
    lab.timestamp_manifest = {"version": "1.0.0", "blobHash": digest}
    stream_response = ota.requests.get
    monkeypatch.setattr(ota, "_fetch_package_id_by_name", lambda name: name)
    monkeypatch.setattr(ota, "_get_auth_context", lambda: (base, {"X-Test": "user"}))

    def get(url, **kwargs):
        if url == base + "/packages/primary/manifests/at":
            response = MagicMock()
            response.json.return_value = {"data": lab.timestamp_manifest}
            return response
        assert url == base + f"/blobs/{digest}/download"
        return stream_response(base + "/packages/primary/download", **kwargs)

    monkeypatch.setattr(ota.requests, "get", get)
    return lab


def download_timestamp(lab, transaction):
    return ota.download_package_at_timestamp(
        "primary", "2026-10-21", "release", lab.install, transaction=transaction
    )


@pytest.mark.parametrize("cache_mode", ["explicit", "omitted", "none"])
@pytest.mark.parametrize("has_version", [True, False])
def test_timestamp_cache_selection_and_zip_declared_version(
    timestamp_lab, cache_mode, has_version
):
    lab = timestamp_lab
    if not has_version:
        lab.timestamp_manifest.pop("version")
    options = {}
    if cache_mode != "omitted":
        options["download_cache_dir"] = lab.cache if cache_mode == "explicit" else None
    expected = lab.cache if cache_mode == "explicit" else lab.workspace / "install"
    with prepare(lab, **options) as transaction:
        result = download_timestamp(lab, transaction)
        assert result["version"] == "1.0.0"
        assert result["otaMetadata"]["source"] == "timestamp"
        assert transaction.packages == {"release": {"primary"}}
        assert not transaction.committed
        directory = lab.context.package_dir(
            transaction.package_base, "primary", "release"
        )
        assert (directory / "payload.txt").read_text() == "primary"
        assert len(lab.artifacts) == 2
        assert all(path.parent == expected for path in lab.artifacts)
        assert list(expected.iterdir()) == []
        assert not (
            lab.workspace / "install" if cache_mode == "explicit" else lab.cache
        ).exists()
    assert not lab.install.exists()


def test_timestamp_partial_and_resume_state_stay_in_explicit_cache(timestamp_lab):
    lab = timestamp_lab
    lab.interrupted = True
    with prepare(lab, download_cache_dir=lab.cache) as transaction:
        assert download_timestamp(lab, transaction) is None
    partial = lab.cache / "primary-ota-1.0.0.zip.part"
    state = partial.with_name(partial.name + ".json")
    assert partial.stat().st_size == 31
    assert state.is_file()
    assert not (lab.workspace / "install").exists()
    lab.interrupted = False
    with prepare(lab, download_cache_dir=lab.cache) as transaction:
        assert download_timestamp(lab, transaction)["version"] == "1.0.0"
    resumed = lab.requests[-1][1]
    assert resumed["Range"] == "bytes=31-"
    assert "If-Range" in resumed
    assert not partial.exists() and not state.exists()
    assert not (lab.workspace / "install").exists()


def test_timestamp_unusable_explicit_cache_does_not_fall_back(timestamp_lab):
    lab = timestamp_lab
    lab.cache.parent.mkdir(parents=True)
    lab.cache.write_text("not a directory")
    with prepare(lab, download_cache_dir=lab.cache) as transaction:
        assert download_timestamp(lab, transaction) is None
    assert lab.cache.read_text() == "not a directory"
    assert not lab.requests
    assert not (lab.workspace / "install").exists()


def test_a_preparation_cut_off_mid_download_resumes_from_where_it_stopped(archive_lab):
    """raisin-ota-agent#165 review: a download done with the robot on resumes.

    The agent prepares with the robot running, and a radio link drops. The
    cycle that failed is discarded (`discard_prepared_install` removes only the
    staged generation), so the partial and its digest must survive it, and the
    next preparation must ask for the rest with `Range` rather than start over.
    """
    lab = archive_lab
    lab.interrupted = True
    assert ota.prepare_archive_install(
        "release", lab.install, archive_name="test-robot", archive_version="2026.10.19"
    ) is None
    # The link dropped 31 bytes into the first package; the rest never started.
    (partial,) = (lab.workspace / "install").glob("*-ota-1.0.0.zip.part")
    state = partial.with_name(partial.name + ".json")
    assert partial.stat().st_size == 31
    assert state.is_file()
    first = partial.name.split("-ota-", 1)[0]

    lab.interrupted = False
    prepared = ota.prepare_archive_install(
        "release", lab.install, archive_name="test-robot", archive_version="2026.10.19"
    )
    assert prepared is not None
    resumed = [headers for name, headers in lab.requests if name == first][-1]
    assert resumed["Range"] == "bytes=31-"
    assert "If-Range" in resumed
    assert not partial.exists()
    ota.discard_prepared_install(prepared)
