"""
cppcheck static-analysis command for RAISIN.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import click

from commands import globals as g
from commands.test import _resolve_build_dir
from commands.utils import get_build_jobs

# Checks to enable in cppcheck
_ENABLE = "warning,performance,portability" # style is disabled now

# subtrees to skip (always)
_IGNORE_SUBTREES = [
    "generated",
]

# Any directory whose name contains one of these substrings (case-insensitive)
# is treated as a third-party subtree and skipped.
_IGNORE_DIR_TOKENS = [
    "thirdparty",
    "third_party",
    "3rdparty",
]

# Directory names that are pruned while scanning for third-party subtrees, so
# the walk stays fast and never descends into build/dependency output.
_SCAN_PRUNE_DIRS = {
    ".git",
    ".cache",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "install",
    "node_modules",
}


def _discover_ignore_subtrees(root: Path) -> list:
    """Find directories under root whose name marks a third-party subtree."""
    found = []
    for dirpath, dirnames, _ in os.walk(root):
        # Prune noisy directories in place so os.walk does not descend.
        dirnames[:] = [d for d in dirnames if d not in _SCAN_PRUNE_DIRS]
        for name in list(dirnames):
            low = name.lower()
            if any(token in low for token in _IGNORE_DIR_TOKENS):
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                found.append(rel)
                # Do not descend into a subtree we are already skipping.
                dirnames.remove(name)
    return found

# External/system locations to skip
_SUPPRESS_PATH_GLOBS = [
    "*/usr/*",       # system headers (pcl, eigen, gstreamer, libstdc++, ...)
    "*/.cache/*",    # vcpkg-installed dependencies
    "*/install/*",   # raisin install prefix
]


def _cppcheck_preflight() -> None:
    """Ensure cppcheck is available."""
    if shutil.which("cppcheck") is None:
        raise click.ClickException(
            "cppcheck not found. Install it first:\n  sudo apt-get install cppcheck"
        )


def _resolve_compile_db(build_dir: Path) -> Path:
    """Produce a complete compile database for build_dir."""
    compile_db = build_dir / "compile_commands.json"
    ninja = shutil.which("ninja")
    build_ninja = build_dir / "build.ninja"
    if ninja and build_ninja.is_file():
        try:
            proc = subprocess.run(
                [ninja, "-t", "compdb"],
                cwd=str(build_dir),
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            compile_db.write_text(proc.stdout, encoding="utf-8")
            return compile_db
        except subprocess.CalledProcessError as e:
            click.echo(
                f"⚠️  'ninja -t compdb' failed ({e}); falling back to the existing "
                "compile_commands.json.",
                err=True,
            )

    if not compile_db.is_file():
        raise click.ClickException(
            f"compile_commands.json not found in: {build_dir}\n"
            "Build the project first, e.g.: raisin build -t <build type>"
        )
    return compile_db


def _generate_html(xml_path: Path, report_dir: Path, source_dir: Path):
    """Convert a cppcheck XML report into a browsable HTML report in report_dir."""
    if shutil.which("cppcheck-htmlreport") is None:
        click.echo(
            "⚠️  cppcheck-htmlreport not found; skipping HTML (report.xml still "
            "written). It ships with the cppcheck package.",
            err=True,
        )
        return None
    subprocess.run(
        [
            "cppcheck-htmlreport",
            f"--file={xml_path}",
            f"--report-dir={report_dir}",
            f"--source-dir={source_dir}",
            "--title=RAISIN cppcheck",
        ],
        check=False,
        text=True,
    )
    index = report_dir / "index.html"
    return index if index.is_file() else None


def run_cppcheck(
    build_type: Optional[str],
    jobs: int,
    strict: bool = False,
    report_dir: str = "cppcheck-report",
    html: bool = True,
) -> None:
    _cppcheck_preflight()

    root = Path(g.script_directory)
    build_dir = _resolve_build_dir(build_type)
    if not build_dir.is_dir():
        build_type_for_message = (build_type or "release").lower().strip() or "release"
        raise click.ClickException(
            f"Build directory not found: {build_dir}\n"
            f"Run: raisin build -t {build_type_for_message}"
        )
    compile_db = _resolve_compile_db(build_dir)

    cache_dir = build_dir / "cppcheck-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    suppressions = root / "cppcheck-suppressions.txt"

    # XML and HTML reports all live under one directory.
    report_path = Path(report_dir)
    if not report_path.is_absolute():
        report_path = root / report_path
    report_path.mkdir(parents=True, exist_ok=True)
    xml_path = report_path / "report.xml"

    cmd = [
        "cppcheck",
        f"--project={compile_db}",
        f"--enable={_ENABLE}",
        "--inline-suppr",
        "--suppress=missingIncludeSystem",
        "--std=c++20",
        f"-j{jobs}",
        f"--cppcheck-build-dir={cache_dir}",
        "--xml",
        "--quiet",
    ]
    if suppressions.is_file():
        cmd.append(f"--suppressions-list={suppressions}")
    ignore_subtrees = _IGNORE_SUBTREES + _discover_ignore_subtrees(root)
    for rel in ignore_subtrees:
        rel = rel.replace(os.sep, "/")
        cmd.append(f"-i{root / rel}")
        cmd.append(f"--suppress=*:*/{rel}/*")
    for glob in _SUPPRESS_PATH_GLOBS:
        cmd.append(f"--suppress=*:{glob}")
    if strict:
        cmd.append("--error-exitcode=1")

    click.echo(f"🔎 Running cppcheck on {compile_db}")

    # cppcheck emits the XML report on stderr; capture it into report_dir.
    result = subprocess.run(cmd, cwd=str(root), text=True, stderr=subprocess.PIPE)
    diagnostics = result.stderr or ""
    xml_path.write_text(diagnostics, encoding="utf-8")
    n_findings = diagnostics.count("<error ")
    click.echo(f"📝 {n_findings} finding(s) written as XML to: {xml_path}")

    if html:
        index = _generate_html(xml_path, report_path, root)
        if index is not None:
            click.echo(f"🌐 HTML report: {index}")

    if strict and result.returncode != 0:
        raise click.ClickException("cppcheck reported findings (strict mode).")

    if result.returncode == 0:
        click.echo("✅ cppcheck finished.")
    else:
        # Report-only: surface the non-zero code but do not fail the command.
        click.echo(
            f"⚠️  cppcheck exited with code {result.returncode} (report-only).",
            err=True,
        )


@click.command(name="cppcheck")
@click.argument(
    "build_type",
    required=False,
    type=click.Choice(["debug", "release"], case_sensitive=False),
)
@click.option(
    "--jobs",
    "-j",
    default=None,
    type=int,
    help="Parallel analysis jobs (default: auto, same as the build).",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Exit non-zero if cppcheck reports any finding (for CI). "
    "Default is report-only (always exits 0).",
)
@click.option(
    "--report-dir",
    "-o",
    default="cppcheck-report",
    show_default=True,
    help="Directory (relative to repo root) for the report. report.xml and the "
    "HTML report are written here together.",
)
@click.option(
    "--html/--no-html",
    default=True,
    help="Also generate a browsable HTML report (default) via "
    "cppcheck-htmlreport, alongside report.xml.",
)
def cppcheck_command(
    build_type: Optional[str],
    jobs: Optional[int],
    strict: bool,
    report_dir: str,
    html: bool,
) -> None:
    """
    Run cppcheck static analysis over the project's compile database.

    \b
    Examples:
        python3 raisin.py cppcheck                   # release build -> cppcheck-report/
        python3 raisin.py cppcheck debug             # analyze the debug build
        python3 raisin.py cppcheck --strict          # fail (exit 1) on findings

    \b
    Requires a build first (for compile_commands.json): raisin build -t release
    """
    try:
        run_cppcheck(
            build_type,
            jobs=jobs if jobs and jobs > 0 else get_build_jobs(),
            strict=strict,
            report_dir=report_dir,
            html=html,
        )
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e)) from e
