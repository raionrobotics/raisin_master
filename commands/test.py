"""
Test command for RAISIN.

Runs the GoogleTest executables built by CMake: unit tests (names ending in
`_unittest`) and integration tests (names ending in `_inttest`). By default
both run (unit first); --unit / --integration restrict to one kind. The
coverage report (--coverage) stays unit-test driven.
"""

import os
import platform
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import click
from typing import Optional

from commands import globals as g


# Test-executable name suffixes, in run order (unit first, then integration).
UNIT_SUFFIX = "_unittest"
INTEGRATION_SUFFIX = "_inttest"
ALL_SUFFIXES = (UNIT_SUFFIX, INTEGRATION_SUFFIX)


def _is_test_executable(path: Path, suffix: str) -> bool:
    if not path.is_file():
        return False
    if not path.stem.endswith(suffix):
        return False
    if platform.system().lower() == "windows":
        return path.suffix.lower() in {".exe", ".bat", ".cmd"}
    return os.access(path, os.X_OK)


def _is_unittest_executable(path: Path) -> bool:
    # Kept for the coverage path, which is unit-test driven.
    return _is_test_executable(path, UNIT_SUFFIX)


def _discover_tests(build_dir: Path, suffixes) -> list:
    """Collect test executables under build_dir, ordered by suffix (the order in
    `suffixes`, i.e. unit before integration) then path."""
    found = []
    seen = set()
    for suffix in suffixes:
        for p in sorted(build_dir.rglob(f"*{suffix}*"), key=lambda p: str(p)):
            # Skip CMake's internal scratch dirs (TryCompile artifacts, compiler
            # checks) which can contain binaries whose names match the suffix.
            if p in seen or "CMakeFiles" in p.parts:
                continue
            if _is_test_executable(p, suffix):
                seen.add(p)
                found.append(p)
    return found


def _get_build_dir_from_config(build_type: str) -> Path:
    config_path = Path(g.script_directory) / "configuration_setting.yaml"
    if not config_path.is_file():
        return Path(g.script_directory) / f"cmake-build-{build_type}"

    try:
        import yaml
    except ImportError as e:
        raise click.ClickException(
            "Missing dependency 'pyyaml'; required to read configuration_setting.yaml"
        ) from e

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        raise click.ClickException(f"Failed to read {config_path}: {e}") from e

    key = "release_build_dir" if build_type == "release" else "debug_build_dir"
    raw = config.get(key)
    if not raw:
        return Path(g.script_directory) / f"cmake-build-{build_type}"

    build_dir = Path(str(raw))
    if not build_dir.is_absolute():
        build_dir = (Path(g.script_directory) / build_dir).resolve()
    return build_dir


def _resolve_build_dir(build_type: Optional[str]) -> Path:
    preferred = (build_type or "release").lower().strip() or "release"
    build_dir = _get_build_dir_from_config(preferred)

    if not build_dir.is_dir() and not build_type and preferred == "release":
        debug_dir = _get_build_dir_from_config("debug")
        if debug_dir.is_dir():
            click.echo(
                f"⚠️  {build_dir} not found; falling back to {debug_dir}",
                err=True,
            )
            build_dir = debug_dir
    return build_dir


def _coverage_preflight(build_dir: Path):
    """Validate the environment/data needed for coverage; return list of *.gcda."""
    if platform.system().lower() == "windows":
        raise click.ClickException(
            "Coverage is only supported on Linux/gcc (MSVC does not support --coverage)."
        )

    if shutil.which("gcovr") is None:
        raise click.ClickException(
            "gcovr not found. Install it first:\n  sudo apt-get install gcovr"
        )

    # *.gcno is emitted at compile time for every instrumented file; *.gcda only
    # when code runs. Accept either so a coverage build with not-yet-run (0%)
    # sources still reports instead of bailing out.
    coverage_files = list(build_dir.rglob("*.gcno")) + list(build_dir.rglob("*.gcda"))
    if not coverage_files:
        raise click.ClickException(
            f"No coverage data (*.gcno/*.gcda) found under: {build_dir}\n"
            "The binaries were not built with coverage instrumentation.\n"
            "Please insert raisin_enable_coverage(PROJECT_NAME) in CMakeLists.txt\n\n"
        )
    return coverage_files


def _resolve_output_dir(coverage_output: str) -> Path:
    root = Path(g.script_directory)
    output_dir = Path(coverage_output)
    if not output_dir.is_absolute():
        output_dir = root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


# Paths excluded from coverage even though they live under a package directory
COVERAGE_EXCLUDE_PATTERNS = [
    r".*/third_party/.*",
    r".*/3rdparty/.*",
]


def _run_gcovr_html(build_dir: Path, root: Path, filter_pattern: str, index: Path) -> str:
    """Run gcovr to write an --html-details report; return its stdout summary."""
    index.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "gcovr",
        "--root",
        str(root),
        "--filter",
        filter_pattern,
        # Tolerate gcov's negative-branch-count bug (GCC #68080); warn instead
        # of aborting so the report is still produced.
        "--gcov-ignore-parse-errors=negative_hits.warn_once_per_file",
        "--html-details",
        "-o",
        str(index),
        "--print-summary",
        str(build_dir),
    ]
    for pattern in COVERAGE_EXCLUDE_PATTERNS:
        cmd.extend(["--exclude", pattern])
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise click.ClickException(
            f"gcovr failed with exit code {e.returncode}\n{e.stderr or ''}"
        ) from e
    return proc.stdout or ""


def _parse_line_coverage(gcovr_stdout: str):
    """Extract (percent, covered, total) from gcovr --print-summary output."""
    m = re.search(r"lines:\s*([\d.]+)%\s*\((\d+)\s+out of\s+(\d+)\)", gcovr_stdout)
    if not m:
        return None
    return float(m.group(1)), int(m.group(2)), int(m.group(3))


def _packages_with_tests(build_dir: Path):
    """Return the set of src-relative package paths that have a unit test target.

    A package "has test code" when a built `*_unittest` executable lives under
    its build subtree, e.g. <build>/src/raisin/raisin_network/raisin_network_unittest.
    """
    tested = set()
    for exe in build_dir.rglob("*_unittest*"):
        if not _is_unittest_executable(exe):
            continue
        parts = exe.relative_to(build_dir).parts
        if "CMakeFiles" in parts:
            pkg_parts = parts[: parts.index("CMakeFiles")]
        else:
            pkg_parts = parts[:-1]  # directory containing the executable
        if pkg_parts and pkg_parts[0] == "src" and len(pkg_parts) > 1:
            tested.add("/".join(pkg_parts))
    return tested


def _discover_coverage_modules(build_dir: Path):
    """Map each instrumented package to its source path, based on *.gcno layout.

    Build output mirrors the source tree, e.g.
        <build>/src/raisin/raisin_network/CMakeFiles/<target>.dir/.../foo.cpp.gcno
    so the package directory is the path before 'CMakeFiles' (relative to build).
    Returns a dict: {module_name: src_relative_path} sorted by name.

    Discovery keys off *.gcno (emitted at compile time for every instrumented
    file) rather than *.gcda (only written when code actually runs). This way a
    package whose files were instrumented but never executed still shows up, so
    its sources are reported at 0% instead of being silently dropped.

    Packages that have no unit test of their own are skipped (even if their code
    was exercised transitively by another package's test).
    """
    pkg_rels = set()
    for gcno in build_dir.rglob("*.gcno"):
        parts = gcno.relative_to(build_dir).parts
        if "CMakeFiles" not in parts:
            continue
        pkg_parts = parts[: parts.index("CMakeFiles")]
        if pkg_parts and pkg_parts[0] == "src" and len(pkg_parts) > 1:
            pkg_rels.add("/".join(pkg_parts))

    tested = _packages_with_tests(build_dir)
    pkg_rels &= tested

    # Assign short, unique module names (basename; disambiguate on collision).
    by_name: dict = {}
    for rel in sorted(pkg_rels):
        name = rel.rsplit("/", 1)[-1]
        if name in by_name:
            # collision: fall back to last two path components
            name = "_".join(rel.split("/")[-2:])
        by_name[name] = rel
    return by_name


def _write_module_landing(output_dir: Path, rows) -> Path:
    """Write a simple landing page linking each per-module report."""
    rows = sorted(rows, key=lambda r: r["name"])

    def color(pct):
        if pct is None:
            return "#888"
        return "#2e7d32" if pct >= 80 else "#f9a825" if pct >= 50 else "#c62828"

    body = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>RAISIN coverage by module</title>",
        "<style>body{font-family:sans-serif;margin:2rem;}"
        "table{border-collapse:collapse;}th,td{padding:6px 14px;border:1px solid #ddd;}"
        "th{background:#f5f5f5;text-align:left;}a{text-decoration:none;}</style></head><body>",
        "<h1>Coverage by module</h1>",
        "<table><tr><th>Module</th><th>Line coverage</th><th>Lines</th><th>Source</th></tr>",
    ]
    for r in rows:
        pct = r["percent"]
        pct_txt = f"{pct:.1f}%" if pct is not None else "n/a"
        lines_txt = (
            f"{r['covered']}/{r['total']}" if r["total"] is not None else "-"
        )
        body.append(
            f"<tr><td><a href='{r['name']}/index.html'>{r['name']}</a></td>"
            f"<td style='color:{color(pct)};font-weight:bold'>{pct_txt}</td>"
            f"<td>{lines_txt}</td><td><code>{r['src']}</code></td></tr>"
        )
    body.append("</table></body></html>")

    landing = output_dir / "index.html"
    landing.write_text("\n".join(body), encoding="utf-8")
    return landing


def _generate_coverage_report_per_module(
    build_dir: Path, coverage_output: str
) -> None:
    """Generate one HTML coverage report per instrumented package (module)."""
    _coverage_preflight(build_dir)
    root = Path(g.script_directory)
    output_dir = _resolve_output_dir(coverage_output)

    modules = _discover_coverage_modules(build_dir)
    if not modules:
        raise click.ClickException(
            f"No instrumented modules with their own unit test found under: {build_dir}"
        )

    click.echo(f"\n📊 Generating per-module coverage for {len(modules)} module(s)...")
    rows = []
    for name, src_rel in modules.items():
        module_out = output_dir / name / "index.html"
        summary = _run_gcovr_html(build_dir, root, src_rel + "/", module_out)
        parsed = _parse_line_coverage(summary)
        pct, covered, total = parsed if parsed else (None, None, None)
        rows.append(
            {"name": name, "src": src_rel, "percent": pct, "covered": covered, "total": total}
        )
        pct_txt = f"{pct:.1f}%" if pct is not None else "n/a"
        click.echo(f"   • {name:35s} {pct_txt:>7}  → {module_out}")

    landing = _write_module_landing(output_dir, rows)
    click.echo(f"✅ Per-module reports written under: {output_dir}")
    click.echo(f"   Landing page: {landing}")


def _pkg_label_for_exe(exe: Path, build_dir: Path) -> str:
    """Short package name a test executable belongs to (for grouping)."""
    parts = exe.relative_to(build_dir).parts
    if "CMakeFiles" in parts:
        pkg_parts = parts[: parts.index("CMakeFiles")]
    else:
        pkg_parts = parts[:-1]
    if pkg_parts and pkg_parts[0] == "src" and len(pkg_parts) > 1:
        return pkg_parts[-1]
    return exe.stem


def _parse_gtest_xml(path: Path):
    """Parse a gtest JUnit XML; return per-binary counts or None on failure."""
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return None

    def gi(key):
        try:
            return int(root.get(key, 0) or 0)
        except ValueError:
            return 0

    return {"tests": gi("tests"), "failed": gi("failures") + gi("errors"), "disabled": gi("disabled")}


def _aggregate_test_results(results) -> dict:
    """Roll up per-executable results into per-package counts."""
    agg: dict = {}
    for r in results:
        a = agg.setdefault(
            r["label"],
            {"tests": 0, "passed": 0, "failed": 0, "disabled": 0, "crashed": False},
        )
        data = _parse_gtest_xml(r["xml"]) if r["xml"] and r["xml"].is_file() else None
        if data:
            a["tests"] += data["tests"]
            a["failed"] += data["failed"]
            a["passed"] += data["tests"] - data["failed"]
            a["disabled"] += data["disabled"]
        else:
            # No XML written -> the binary crashed/timed out before finishing.
            a["crashed"] = True
    return agg


def _print_test_table(agg: dict) -> None:
    """Print a per-package pass/fail summary table to the console."""
    name_w = max([len("Package")] + [len(n) for n in agg]) + 2
    header = f"{'Package':<{name_w}}{'Tests':>7}{'Pass':>7}{'Fail':>7}{'Disabled':>10}"
    click.echo("\n" + header)
    click.echo("─" * len(header))
    tot = {"tests": 0, "passed": 0, "failed": 0, "disabled": 0}
    for name, a in sorted(agg.items()):
        for k in tot:
            tot[k] += a[k]
        line = f"{name:<{name_w}}{a['tests']:>7}{a['passed']:>7}{a['failed']:>7}{a['disabled']:>10}"
        if a["crashed"]:
            line += "  (crashed/timeout)"
        click.echo(click.style(line, fg="red" if a["failed"] or a["crashed"] else "green"))
    click.echo("─" * len(header))
    click.echo(f"{'TOTAL':<{name_w}}{tot['tests']:>7}{tot['passed']:>7}{tot['failed']:>7}{tot['disabled']:>10}")


def _write_test_report_md(report_dir: Path, agg: dict) -> Path:
    """Write the per-package pass/fail summary (same as the console table) as Markdown."""
    lines = ["# Unit test report", "", "| Package | Tests | Pass | Fail | Disabled |", "|---|--:|--:|--:|--:|"]
    tot = {"tests": 0, "passed": 0, "failed": 0, "disabled": 0}
    for name, a in sorted(agg.items()):
        for k in tot:
            tot[k] += a[k]
        note = " (crashed/timeout)" if a["crashed"] else ""
        lines.append(f"| {name}{note} | {a['tests']} | {a['passed']} | {a['failed']} | {a['disabled']} |")
    lines.append(f"| **TOTAL** | **{tot['tests']}** | **{tot['passed']}** | **{tot['failed']}** | **{tot['disabled']}** |")

    path = report_dir / "report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run_unittests(
    build_type: Optional[str],
    suffixes=ALL_SUFFIXES,
    coverage_output: str = "coverage-report",
    coverage: bool = False,
    timeout: int = 600,
    report: bool = False,
    report_output: str = "test-report",
) -> None:
    requested = (build_type or "").lower().strip()
    if requested and requested not in {"debug", "release"}:
        raise click.ClickException("build_type must be 'debug' or 'release'")

    build_dir = _resolve_build_dir(build_type)

    if not build_dir.is_dir():
        build_type_for_message = requested or "release"
        raise click.ClickException(
            f"Build directory not found: {build_dir}\n"
            f"Run: python3 raisin.py build --type {build_type_for_message}"
        )

    executables = _discover_tests(build_dir, suffixes)

    if not executables:
        raise click.ClickException(
            f"No test executables found under: {build_dir}\n"
            f"Expected files whose name ends with one of: {', '.join(suffixes)}."
        )

    suffix_names = {UNIT_SUFFIX: "unit", INTEGRATION_SUFFIX: "integration"}
    kinds = " + ".join(suffix_names.get(s, s.lstrip("_")) for s in suffixes)
    click.echo(f"🧪 Running {len(executables)} {kinds} test(s) in {build_dir}")

    # With --report, have each gtest binary emit JUnit XML to aggregate later.
    xml_dir = None
    results = []
    if report:
        report_path = _resolve_output_dir(report_output)
        xml_dir = report_path / "xml"
        if xml_dir.is_dir():
            shutil.rmtree(xml_dir)
        xml_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    for exe in executables:
        click.echo(f"\n▶ {exe}")
        cmd = [str(exe)]
        xml_file = None
        if report:
            label = _pkg_label_for_exe(exe, build_dir)
            xml_file = xml_dir / f"{label}__{exe.stem}.xml"
            cmd.append(f"--gtest_output=xml:{xml_file}")
        status = "pass"
        try:
            # timeout=0 disables the limit; otherwise a hung test is killed
            # (SIGKILL) after `timeout` seconds, marked failed, and we move on.
            subprocess.run(
                cmd,
                cwd=build_dir,
                check=True,
                timeout=(timeout if timeout > 0 else None),
            )
        except subprocess.TimeoutExpired:
            failures += 1
            status = "timeout"
            click.echo(
                f"⏱️  Timed out after {timeout}s (killed): {exe}", err=True
            )
        except subprocess.CalledProcessError as e:
            failures += 1
            status = "fail"
            click.echo(f"❌ Failed with exit code {e.returncode}: {exe}", err=True)
        if report:
            results.append({"label": _pkg_label_for_exe(exe, build_dir), "status": status, "xml": xml_file})

    if failures:
        click.echo(f"\n⚠️  {failures} test(s) failed.", err=True)
    else:
        click.echo("\n✅ All tests passed.")

    if report:
        agg = _aggregate_test_results(results)
        _print_test_table(agg)
        click.echo(f"\n📝 Test report: {_write_test_report_md(report_path, agg)}")

    # Generate the coverage report even if some tests failed, so partial
    # coverage is still available. Done before raising on failures.
    if coverage:
        _generate_coverage_report_per_module(build_dir, coverage_output)

    if failures:
        raise click.ClickException(f"{failures} test(s) failed.")


@click.command(name="test")
@click.argument(
    "build_type",
    required=False,
    type=click.Choice(["debug", "release"], case_sensitive=False),
)
@click.option(
    "--unit", "only_unit", is_flag=True,
    help="Run only unit tests (executables ending in _unittest).",
)
@click.option(
    "--integration", "only_integration", is_flag=True,
    help="Run only integration tests (executables ending in _inttest).",
)
@click.option(
    "--coverage-output",
    default="coverage-report",
    show_default=True,
    help="Directory to write the HTML report (index.html) into.",
)
@click.option(
    "--coverage",
    is_flag=True,
    default=False,
    help="Generate an HTML line-coverage report (gcovr) per package/module "
    "(coverage-report/<module>/index.html) plus a landing page, after running "
    "tests. Requires a build configured with -DRAISIN_BUILD_TEST=ON (Linux/gcc).",
)
@click.option(
    "--timeout",
    default=600,
    show_default=True,
    type=int,
    help="Per-test-executable timeout in seconds; a test exceeding it is killed "
    "and marked failed (so a hung test cannot block the run). Use 0 to disable.",
)
@click.option(
    "--report",
    is_flag=True,
    default=False,
    help="Collect per-package pass/fail counts (gtest XML), print a console "
    "table, and save it as Markdown (test-report/report.md).",
)
@click.option(
    "--report-output",
    default="test-report",
    show_default=True,
    help="Directory for the --report output (report.md + xml/).",
)
def test_command(
    build_type: Optional[str],
    only_unit: bool,
    only_integration: bool,
    coverage_output: str,
    coverage: bool,
    timeout: int,
    report: bool,
    report_output: str,
) -> None:
    """
    Run tests from the CMake build folder.

    By default runs BOTH unit (*_unittest) and integration (*_inttest) tests,
    unit first. Use --unit or --integration to run only one kind.

    \b
    Examples:
        python3 raisin.py test               # unit + integration (release)
        python3 raisin.py test debug         # unit + integration (debug)
        python3 raisin.py test --unit        # unit tests only
        python3 raisin.py test --integration # integration tests only
        python3 raisin.py test --coverage    # run tests + per-module coverage report
        python3 raisin.py test --report      # per-package pass/fail table + report.md
        python3 raisin.py test --timeout 60  # kill any test hung longer than 60 s

    """
    if only_unit and only_integration:
        raise click.ClickException("--unit and --integration are mutually exclusive")

    if only_unit:
        suffixes = (UNIT_SUFFIX,)
    elif only_integration:
        suffixes = (INTEGRATION_SUFFIX,)
    else:
        suffixes = ALL_SUFFIXES

    try:
        run_unittests(
            build_type,
            suffixes=suffixes,
            coverage_output=coverage_output,
            coverage=coverage,
            timeout=timeout,
            report=report,
            report_output=report_output,
        )
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e)) from e
