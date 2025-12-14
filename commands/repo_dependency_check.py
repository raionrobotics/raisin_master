"""
Repo dependency validation for RAISIN.

Validates that each repo's `src/<repo>/release.yaml:dependencies` includes all repos
required by the repo's packages as inferred from `raisin_find_package(...)` calls.

Optionally offers an autofix prompt to append missing dependencies (with versions).
"""

import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import click
import yaml

from commands import globals as g

try:
    from packaging.requirements import Requirement
except Exception:  # pragma: no cover
    Requirement = None  # type: ignore[assignment]


_CMAKE_RAISIN_FIND_PACKAGE_RE = re.compile(
    r"(?i)\braisin_find_package\s*\(\s*([A-Za-z0-9_.+-]+)\b"
)
_FALLBACK_NAME_RE = re.compile(r"^([A-Za-z0-9_.+-]+)")
_RELEASE_DEP_INLINE_RE = re.compile(r"^(\s*dependencies:\s*)\[(.*)\]\s*$")


def _normalize_dependency_name(spec: str) -> str:
    spec = str(spec).strip()
    if not spec:
        return spec
    if Requirement is not None:
        try:
            return Requirement(spec).name
        except Exception:
            pass
    m = _FALLBACK_NAME_RE.match(spec)
    return m.group(1) if m else spec


def _discover_repo_dirs(src_dir: Path, repos_to_ignore: Set[str]) -> List[Path]:
    if not src_dir.is_dir():
        return []
    repos = [p for p in src_dir.iterdir() if p.is_dir() and p.name not in repos_to_ignore]
    return sorted(repos, key=lambda p: p.name)


def _find_package_dirs(repo_dir: Path, packages_to_ignore: Set[str]) -> List[Path]:
    candidates: List[Path] = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [
            d
            for d in dirs
            if d
            not in {
                ".git",
                "build",
                "cmake-build-debug",
                "cmake-build-release",
                "__pycache__",
            }
            and d not in packages_to_ignore
        ]
        if "CMakeLists.txt" in files:
            candidates.append(Path(root))

    candidates.sort(key=lambda p: len(p.parts))
    package_dirs: List[Path] = []
    for candidate in candidates:
        if any(candidate == pkg or candidate.is_relative_to(pkg) for pkg in package_dirs):
            continue
        package_dirs.append(candidate)
    return package_dirs


def _parse_raisin_find_packages(cmake_lists: Path) -> Set[str]:
    text = cmake_lists.read_text(encoding="utf-8", errors="ignore")
    return {m.group(1) for m in _CMAKE_RAISIN_FIND_PACKAGE_RE.finditer(text)}


def _discover_binary_packages(release_install_dir: Path) -> Dict[str, Tuple[str, Path]]:
    """
    Returns {package_name: (repo_name, evidence_path)} for packages discovered
    in `release/install/**/(lib/cmake|share/*/cmake)`.
    """
    results: Dict[str, Tuple[str, Path]] = {}
    if not release_install_dir.is_dir():
        return results

    for repo_dir in sorted(
        [p for p in release_install_dir.iterdir() if p.is_dir()], key=lambda p: p.name
    ):
        repo_name = repo_dir.name

        for lib_cmake_dir in repo_dir.rglob("lib/cmake"):
            if not lib_cmake_dir.is_dir():
                continue
            for pkg_dir in sorted(
                [p for p in lib_cmake_dir.iterdir() if p.is_dir()], key=lambda p: p.name
            ):
                pkg_name = pkg_dir.name
                if pkg_name not in results:
                    results[pkg_name] = (repo_name, pkg_dir)

        for share_cmake_dir in repo_dir.rglob("share"):
            if not share_cmake_dir.is_dir():
                continue
            for pkg_dir in [p for p in share_cmake_dir.iterdir() if p.is_dir()]:
                cmake_dir = pkg_dir / "cmake"
                if not cmake_dir.is_dir():
                    continue
                pkg_name = pkg_dir.name
                if pkg_name not in results:
                    results[pkg_name] = (repo_name, cmake_dir)

    return results


def _repo_version_from_src(src_dir: Path, repo_name: str) -> Optional[str]:
    release_yaml = src_dir / repo_name / "release.yaml"
    if not release_yaml.is_file():
        return None
    try:
        details = yaml.safe_load(
            release_yaml.read_text(encoding="utf-8", errors="ignore")
        )
    except Exception:
        return None
    if not isinstance(details, dict):
        return None
    v = details.get("version")
    return str(v) if v is not None else None


def _repo_version_from_installed(
    release_install_dir: Path, repo_name: str
) -> Optional[str]:
    repo_dir = release_install_dir / repo_name
    if not repo_dir.is_dir():
        return None

    preferred = (
        repo_dir
        / g.os_type
        / g.os_version
        / g.architecture
        / "release"
        / "release.yaml"
    )
    if preferred.is_file():
        try:
            details = yaml.safe_load(
                preferred.read_text(encoding="utf-8", errors="ignore")
            )
            if isinstance(details, dict) and details.get("version") is not None:
                return str(details["version"])
        except Exception:
            pass

    for p in repo_dir.rglob("release.yaml"):
        try:
            details = yaml.safe_load(p.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(details, dict) and details.get("version") is not None:
                return str(details["version"])
        except Exception:
            continue
    return None


def _repo_version(
    src_dir: Path, release_install_dir: Path, repo_name: str
) -> Optional[str]:
    return _repo_version_from_src(src_dir, repo_name) or _repo_version_from_installed(
        release_install_dir, repo_name
    )


def _update_release_yaml_dependencies_in_place(
    release_yaml: Path, add_specs: List[str]
) -> None:
    text = release_yaml.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines(keepends=True)

    def ensure_trailing_newline(s: str) -> str:
        return s if s.endswith("\n") else s + "\n"

    for i, line in enumerate(lines):
        m = _RELEASE_DEP_INLINE_RE.match(line.rstrip("\n"))
        if not m:
            continue
        prefix, inside = m.group(1), m.group(2).strip()
        existing: List[str] = []
        if inside:
            existing = [part.strip() for part in inside.split(",") if part.strip()]
        updated = existing + add_specs
        lines[i] = ensure_trailing_newline(f"{prefix}[{', '.join(updated)}]")
        release_yaml.write_text("".join(lines), encoding="utf-8")
        return

    for i, line in enumerate(lines):
        if re.match(r"^\s*dependencies:\s*$", line):
            base_indent = re.match(r"^(\s*)", line).group(1)
            item_indent = base_indent + "  "
            j = i + 1
            while j < len(lines):
                if re.match(rf"^{re.escape(base_indent)}\S", lines[j]):
                    break
                j += 1
            insert = "".join(
                [ensure_trailing_newline(f"{item_indent}- {s}") for s in add_specs]
            )
            lines[j:j] = [insert]
            release_yaml.write_text("".join(lines), encoding="utf-8")
            return

    insert_line = ensure_trailing_newline(f"dependencies: [{', '.join(add_specs)}]")
    for i, line in enumerate(lines):
        if re.match(r"^\s*version:\s*", line):
            lines[i + 1 : i + 1] = [insert_line]
            release_yaml.write_text("".join(lines), encoding="utf-8")
            return

    if lines and not lines[-1].endswith("\n"):
        lines[-1] = lines[-1] + "\n"
    lines.append(insert_line)
    release_yaml.write_text("".join(lines), encoding="utf-8")


def guard_src_repo_release_yaml_dependencies(
    packages_to_ignore: List[str],
    repos_to_ignore: List[str],
    _allow_autofix: bool = True,
) -> None:
    """
    Ensures that each repo's `release.yaml:dependencies` includes all other repos
    required by its packages' `raisin_find_package(...)` usage.
    """

    src_dir = Path(g.script_directory) / "src"
    release_install_dir = Path(g.script_directory) / "release" / "install"
    packages_to_ignore_set = set(packages_to_ignore)
    repos_to_ignore_set = set(repos_to_ignore)

    repo_dirs = _discover_repo_dirs(src_dir, repos_to_ignore_set)
    package_dirs_by_repo: Dict[str, List[Path]] = {}
    referenced_package_names: Set[str] = set()

    for repo_dir in repo_dirs:
        repo_name = repo_dir.name
        pkg_dirs = _find_package_dirs(repo_dir, packages_to_ignore_set)
        package_dirs_by_repo[repo_name] = pkg_dirs
        for pkg_dir in pkg_dirs:
            referenced_package_names.update(
                _parse_raisin_find_packages(pkg_dir / "CMakeLists.txt")
            )

    package_sources: Dict[str, List[Tuple[str, Path]]] = defaultdict(list)
    for repo_name, pkg_dirs in package_dirs_by_repo.items():
        for pkg_dir in pkg_dirs:
            pkg_name = pkg_dir.name
            if pkg_name not in referenced_package_names:
                continue
            package_sources[pkg_name].append((repo_name, pkg_dir / "CMakeLists.txt"))

    conflicts = {
        pkg: sources
        for pkg, sources in package_sources.items()
        if len({repo for repo, _ in sources}) > 1
    }
    if conflicts:
        print(
            "❌ Error: Duplicate package directories found across repos for referenced packages."
        )
        for pkg, sources in sorted(conflicts.items()):
            shown = ", ".join(f"{repo} ({path})" for repo, path in sorted(sources))
            print(f"  - {pkg}: {shown}")
        sys.exit(1)

    package_to_repo: Dict[str, str] = {pkg: sources[0][0] for pkg, sources in package_sources.items()}

    binary_pkg_to_repo = _discover_binary_packages(release_install_dir)
    binary_conflicts: Dict[str, List[Tuple[str, Path]]] = defaultdict(list)
    for pkg_name, (repo_name, evidence_path) in binary_pkg_to_repo.items():
        if pkg_name in package_to_repo and package_to_repo[pkg_name] != repo_name:
            binary_conflicts[pkg_name].append((package_to_repo[pkg_name], Path("src")))
            binary_conflicts[pkg_name].append((repo_name, evidence_path))
            continue
        if pkg_name not in package_to_repo:
            package_to_repo[pkg_name] = repo_name

    if binary_conflicts:
        print("❌ Error: Conflicting binary package providers found in `release/install`.")
        for pkg, sources in sorted(binary_conflicts.items()):
            shown = ", ".join(f"{repo} ({path})" for repo, path in sorted(sources))
            print(f"  - {pkg}: {shown}")
        sys.exit(1)

    required_repo_deps: Dict[str, Dict[str, Set[Path]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for repo_name, pkg_dirs in package_dirs_by_repo.items():
        for pkg_dir in pkg_dirs:
            cmake_lists = pkg_dir / "CMakeLists.txt"
            for dep_pkg in _parse_raisin_find_packages(cmake_lists):
                dep_repo = package_to_repo.get(dep_pkg)
                if not dep_repo or dep_repo == repo_name:
                    continue
                required_repo_deps[repo_name][dep_repo].add(cmake_lists)

    errors: Dict[str, Dict[str, Set[Path]]] = defaultdict(lambda: defaultdict(set))
    missing_release_yaml: Set[str] = set()
    invalid_release_yaml: Set[str] = set()
    loaded_release_yaml: Dict[str, dict] = {}

    root = Path(g.script_directory).resolve()
    for repo_name, needed in required_repo_deps.items():
        if not needed:
            continue
        release_yaml = src_dir / repo_name / "release.yaml"
        if not release_yaml.is_file():
            missing_release_yaml.add(repo_name)
            continue

        try:
            details = yaml.safe_load(
                release_yaml.read_text(encoding="utf-8", errors="ignore")
            )
        except Exception:
            invalid_release_yaml.add(repo_name)
            continue
        if not isinstance(details, dict):
            invalid_release_yaml.add(repo_name)
            continue
        loaded_release_yaml[repo_name] = details

        declared_specs = details.get("dependencies") or []
        if isinstance(declared_specs, str):
            declared_specs = [declared_specs]
        declared = {_normalize_dependency_name(s) for s in declared_specs}

        for dep_repo, locations in needed.items():
            if dep_repo not in declared:
                errors[repo_name][dep_repo].update(locations)

    if not (errors or missing_release_yaml or invalid_release_yaml):
        return

    def print_report() -> None:
        print("❌ Error: src repo dependencies are not fully declared in release.yaml.")
        if missing_release_yaml:
            for repo_name in sorted(missing_release_yaml):
                print(f"  - Missing `src/{repo_name}/release.yaml`")
        if invalid_release_yaml:
            for repo_name in sorted(invalid_release_yaml):
                print(f"  - Invalid `src/{repo_name}/release.yaml`")

        for repo_name in sorted(errors.keys()):
            print(f"\nRepo: {repo_name}")
            for dep_repo in sorted(errors[repo_name].keys()):
                locs = []
                for p in sorted(errors[repo_name][dep_repo]):
                    try:
                        locs.append(str(p.resolve().relative_to(root)))
                    except Exception:
                        locs.append(str(p))
                print(
                    f"  - Missing dependency repo '{dep_repo}' (needed by: {', '.join(locs)})"
                )

    print_report()

    should_fix = False
    if _allow_autofix:
        try:
            should_fix = click.confirm(
                "Auto-add missing repo dependencies to each repo's release.yaml?",
                default=False,
                abort=False,
            )
        except Exception:
            should_fix = False

    if should_fix:
        for repo_name in sorted(errors.keys()):
            release_yaml = src_dir / repo_name / "release.yaml"
            details = loaded_release_yaml.get(repo_name)
            if not isinstance(details, dict):
                continue

            declared_specs = details.get("dependencies") or []
            if isinstance(declared_specs, str):
                declared_specs = [declared_specs]
            if not isinstance(declared_specs, list):
                declared_specs = []

            existing_names = {_normalize_dependency_name(s) for s in declared_specs}
            to_add_repos = [
                r for r in sorted(errors[repo_name].keys()) if r not in existing_names
            ]
            to_add: List[str] = []
            for dep_repo in to_add_repos:
                v = _repo_version(src_dir, release_install_dir, dep_repo)
                to_add.append(f"{dep_repo}=={v}" if v else dep_repo)
            if not to_add:
                continue

            _update_release_yaml_dependencies_in_place(release_yaml, to_add)
            print(
                f"✅ Updated `src/{repo_name}/release.yaml` (added: {', '.join(to_add)})"
            )

        guard_src_repo_release_yaml_dependencies(
            packages_to_ignore, repos_to_ignore, _allow_autofix=False
        )
        return

    print("\nFix: add the missing repos to each repo's `release.yaml:dependencies` list.")
    sys.exit(1)

