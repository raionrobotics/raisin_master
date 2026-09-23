"""Fetching a published archive with a build machine's credential.

A robot receives software; a build machine *reads* it. The two have almost
nothing in common beyond the bytes, and this module exists so they do not share
a code path they would each have to be careful in.

    raisin_agent's CI needs the SDK to compile a test fixture against
    (raisin_agent#50). It has no robot identity, no install tree, no version to
    converge to, and nothing to report afterwards.

So this does exactly four things: authenticate with a `pk_` key, find the
archive, download the packages named, and unpack them into one prefix. What it
deliberately does not do is the robot's work -- no generation symlinks, no
desired state, no install session, no snapshot sent back. `download_all_from_archive`
does all of that because a robot needs it, and a build machine inheriting it
would acquire an install history it can never roll back to.

## The prefix is merged, unlike the robot's tree

The robot keeps packages separable (`<base>/<package>/<os>/<version>/`) because
it replaces them one at a time. A build machine wants the opposite: one
directory with `include/`, `lib/` and `generated/` in it, because that is what
`-DRAISIN_SDK_PREFIX=` means to CMake. Package archives are already rooted that
way, so unpacking two of them into one directory is the merge -- no rewriting,
no layout translation.

## Usage

    export RAISIN_PACKAGE_KEY=pk_...
    python -m raisin_ota.build_machine \
        --archive raisin-robot --platform ubuntu-24.04-x86_64 \
        --package raisin --into /opt/raisin-sdk
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Optional, Sequence

import requests

from .client import _download_to_path, _unwrap_response, get_ota_endpoint

#: Where the key is read from. An argument would put a credential in the process
#: table, where `ps` shows it to every user on the machine and CI logs show it to
#: everyone with read access to the run.
PACKAGE_KEY_ENV = "RAISIN_PACKAGE_KEY"

PACKAGE_KEY_HEADER = "x-package-api-key"

#: Every `pk_` credential starts with this, and nothing else does.
PACKAGE_KEY_PREFIX = "pk_"

#: The `pk_` surface hangs under its own prefix, so the operator routes and this
#: one cannot be widened by the same edit. Both hops live under it, which is why
#: only the base moves and no path below does.
READ_SURFACE = "archive-read"


class FetchRefused(Exception):
    """This machine cannot get what it asked for, and why.

    One exception for every refusal -- a missing key, a key of the wrong kind, an
    archive that is not there, a package the archive does not carry -- because
    the caller is a CI step whose only two outcomes are "the SDK is in this
    directory" and "here is the line to read".
    """


def package_key(environ: Optional[dict] = None) -> str:
    """The build machine's credential, checked for kind before it is sent.

    The kinds are separate tables on the server, so a robot key pasted here
    resolves to nothing and comes back 401 -- a true answer to the wrong
    question, and one that sends whoever reads it looking at permissions rather
    than at the line where they pasted the wrong secret. The prefix is the one
    piece of a credential that is safe to name in an error, so it is named.
    """
    env = os.environ if environ is None else environ
    raw = (env.get(PACKAGE_KEY_ENV) or "").strip()

    if not raw:
        raise FetchRefused(
            f"{PACKAGE_KEY_ENV} is not set. A build machine reads published "
            "packages with a `pk_` credential; ask whoever holds `package:manage` "
            "to issue one."
        )

    if not raw.startswith(PACKAGE_KEY_PREFIX):
        kind = raw.split("_", 1)[0] + "_" if "_" in raw else "something else"
        raise FetchRefused(
            f"{PACKAGE_KEY_ENV} holds a {kind} credential, not a "
            f"`{PACKAGE_KEY_PREFIX}` one. Robot, integration and enrolment keys "
            "live on other axes and cannot read packages."
        )

    return raw


def read_base(endpoint: Optional[str] = None) -> str:
    """The base every path below hangs off."""
    root = (endpoint or get_ota_endpoint()).rstrip("/")
    return f"{root}/{READ_SURFACE}"


def _headers(key: str) -> dict:
    return {PACKAGE_KEY_HEADER: key, "Accept": "application/json"}


def resolve_archive(
    archive_name: str,
    platform: str,
    *,
    key: str,
    version: Optional[str] = None,
    endpoint: Optional[str] = None,
    timeout: int = 30,
) -> dict:
    """Find the archive to read, with the packages it carries.

    One request, because the listing answers with `packages` inline -- a caller
    that has found its archive already holds every `packageId` it needs.

    `version` pins exactly and never falls back to the newest. The robot path
    learned that the hard way (`dso 1.0.3` resolved to a sibling archive), and a
    build machine silently compiling against a different SDK than the one its
    repository pinned is the same defect with a slower symptom.
    """
    params = {"name": archive_name, "platform": platform, "status": "available"}
    if version:
        # Either spelling of the pin means the same archive; the server stores
        # one of them.
        params["version"] = version.lstrip("vV")

    response = requests.get(
        f"{read_base(endpoint)}/archives",
        headers=_headers(key),
        params=params,
        timeout=timeout,
    )
    if response.status_code in (401, 403):
        raise FetchRefused(
            f"The server refused this credential ({response.status_code}). It may "
            "be revoked, expired, or scoped to a tenant that does not hold "
            f"'{archive_name}'."
        )
    response.raise_for_status()

    payload = _unwrap_response(response.json())
    archives = payload.get("archives", []) if isinstance(payload, dict) else payload

    # Filtered again here, deliberately. The server has been observed to ignore
    # `name` and `platform` when other parameters are present and answer with
    # archives of a different name *and* a different architecture -- which on a
    # build machine is an SDK that links and then crashes somewhere else.
    matching = [
        a
        for a in archives
        if a.get("name") == archive_name and a.get("platform") == platform
    ]

    if not matching:
        pinned = f" at version {version}" if version else ""
        raise FetchRefused(
            f"No available archive named '{archive_name}' for {platform}{pinned}."
        )

    if version:
        wanted = version.lstrip("vV")
        for candidate in matching:
            # `or ""` rather than a dict default: the server sends the key with a
            # null value when the version is unset.
            if (candidate.get("version") or "").lstrip("vV") == wanted:
                return candidate
        raise FetchRefused(
            f"Archive '{archive_name}' has no version {version} for {platform}."
        )

    # Newest by publication time, which is the order the server lists in -- not
    # the highest version number. Said plainly because the two differ whenever a
    # fix is published against an older line.
    return matching[0]


def _entries_within(archive: zipfile.ZipFile, into: Path) -> None:
    """Refuse a package that would write outside the prefix it is unpacked into.

    `extractall` resolves `../` relative to the destination, so one entry named
    `../../etc/whatever` in a package escapes it. The robot path guards the
    *package name* for this reason -- `a/../../../../OUTSIDE` put a tree
    anywhere the process could write -- and a merged prefix is the place where
    an entry can do the same thing, since nothing here renames as it unpacks.
    """
    root = into.resolve()
    for name in archive.namelist():
        target = (root / name).resolve()
        if target != root and root not in target.parents:
            raise FetchRefused(
                f"Package entry '{name}' would be written outside {into}."
            )


def _unpack(zip_path: Path, into: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as archive:
        _entries_within(archive, into)
        archive.extractall(into)


def fetch_archive(
    archive_name: str,
    platform: str,
    into: Path,
    *,
    packages: Optional[Sequence[str]] = None,
    version: Optional[str] = None,
    key: Optional[str] = None,
    endpoint: Optional[str] = None,
    clean: bool = False,
) -> dict:
    """Put the named packages of one archive into one prefix.

    Returns `{package_name: {"packageId": ..., "version": ...}}` for what was
    unpacked, so a caller can print or record it.
    """
    key = key or package_key()
    into = Path(into)

    if clean and into.exists():
        shutil.rmtree(into)

    # Refused rather than merged into. Two SDK versions unpacked over each other
    # leave a prefix whose headers and libraries disagree, and the first symptom
    # is a link error a long way from here.
    if into.exists() and any(into.iterdir()):
        raise FetchRefused(
            f"{into} is not empty. Pass --clean to replace it, or choose a "
            "directory this run owns."
        )

    archive = resolve_archive(
        archive_name, platform, key=key, version=version, endpoint=endpoint
    )
    carried = {p.get("packageName"): p for p in archive.get("packages", [])}

    if packages:
        missing = [name for name in packages if name not in carried]
        if missing:
            raise FetchRefused(
                f"Archive '{archive_name}' {archive.get('version')} does not carry "
                f"{', '.join(missing)}. It carries: {', '.join(sorted(carried))}."
            )
        wanted = [carried[name] for name in packages]
    else:
        wanted = list(carried.values())

    if not wanted:
        raise FetchRefused(
            f"Archive '{archive_name}' {archive.get('version')} carries no packages."
        )

    into.mkdir(parents=True, exist_ok=True)
    base = read_base(endpoint)
    archive_id = archive.get("id")
    fetched = {}

    for entry in wanted:
        name = entry.get("packageName")
        package_id = entry.get("packageId")
        download_path = into / f".{name}.download"

        # `_download_to_path` is the robot's primitive and is reused whole: it
        # resumes, verifies the body against the digest the server advertises,
        # and gives up after a bounded number of tries. A build machine wants
        # every one of those; what it does not want is what the robot does
        # afterwards.
        ok, error_code = _download_to_path(
            f"{base}/archives/{archive_id}/packages/{package_id}/download",
            download_path,
            headers=_headers(key),
            error_context=name,
        )
        if not ok:
            raise FetchRefused(f"Downloading '{name}' failed [{error_code}].")

        try:
            _unpack(download_path, into)
        finally:
            download_path.unlink(missing_ok=True)

        fetched[name] = {
            "packageId": package_id,
            "version": entry.get("tagName") or archive.get("version"),
        }
        print(f"✅ {name} {fetched[name]['version']} -> {into}")

    return fetched


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m raisin_ota.build_machine",
        description="Unpack a published archive's packages into one prefix.",
    )
    parser.add_argument("--archive", required=True, help="Archive name")
    parser.add_argument(
        "--platform", required=True, help="e.g. ubuntu-24.04-x86_64"
    )
    parser.add_argument(
        "--into", required=True, type=Path, help="Prefix to unpack into"
    )
    parser.add_argument(
        "--package",
        action="append",
        dest="packages",
        help="Package to unpack; repeatable. Every package in the archive when "
        "omitted, which for an SDK archive is far more than a build needs.",
    )
    parser.add_argument(
        "--version",
        help="Pin an archive version. Omitted means the most recently published.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove the destination first instead of refusing a non-empty one.",
    )
    args = parser.parse_args(argv)

    try:
        fetch_archive(
            args.archive,
            args.platform,
            args.into,
            packages=args.packages,
            version=args.version,
            clean=args.clean,
        )
    except FetchRefused as refused:
        print(f"❌ {refused}", file=sys.stderr)
        return 1
    except requests.RequestException as unreachable:
        print(f"❌ OTA server unreachable: {unreachable}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
