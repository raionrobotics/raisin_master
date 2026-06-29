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
from commands import sanitizer as san
from commands.build_dir import resolve_build_dir


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
    md = _write_coverage_md(root / "report" / "coverage.md", rows)
    click.echo(f"✅ Per-module reports written under: {output_dir}")
    click.echo(f"   Landing page: {landing}")
    click.echo(f"   Markdown summary: {md}")


def _write_coverage_md(out_path: Path, rows) -> Path:
    """Write a per-module line-coverage summary (from gcovr) as Markdown."""
    rows = sorted(rows, key=lambda r: r["name"])
    cov = sum(r["covered"] or 0 for r in rows)
    tot = sum(r["total"] or 0 for r in rows)
    overall = f"{(100.0 * cov / tot):.1f}%" if tot else "n/a"
    lines = [
        "# Coverage report",
        "",
        f"Overall line coverage: **{overall}** ({cov}/{tot} lines across {len(rows)} module(s))",
        "",
        "| Module | Line coverage | Lines | Source |",
        "|---|--:|--:|---|",
    ]
    for r in rows:
        pct = f"{r['percent']:.1f}%" if r["percent"] is not None else "n/a"
        ln = f"{r['covered']}/{r['total']}" if r["total"] is not None else "-"
        lines.append(f"| {r['name']} | {pct} | {ln} | `{r['src']}` |")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


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


def _write_test_report_md(out_path: Path, agg: dict) -> Path:
    """Write the per-package pass/fail summary (same as the console table) as Markdown."""
    lines = ["# Unit test report", "", "| Package | Tests | Pass | Fail | Disabled |", "|---|--:|--:|--:|--:|"]
    tot = {"tests": 0, "passed": 0, "failed": 0, "disabled": 0}
    for name, a in sorted(agg.items()):
        for k in tot:
            tot[k] += a[k]
        note = " (crashed/timeout)" if a["crashed"] else ""
        lines.append(f"| {name}{note} | {a['tests']} | {a['passed']} | {a['failed']} | {a['disabled']} |")
    lines.append(f"| **TOTAL** | **{tot['tests']}** | **{tot['passed']}** | **{tot['failed']}** | **{tot['disabled']}** |")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def _pkg_matches(exe: Path, build_dir: Path, wanted_lower: list) -> bool:
    """True if exe belongs to one of the requested packages (case-insensitive)."""
    label = _pkg_label_for_exe(exe, build_dir).lower()
    parts = [p.lower() for p in exe.relative_to(build_dir).parts]
    return any(w == label or w in parts for w in wanted_lower)


def run_unittests(
    build_type: Optional[str],
    suffixes=ALL_SUFFIXES,
    coverage: bool = False,
    timeout: int = 600,
    sanitizer: str = "off",
    packages=(),
    cppcheck: bool = False,
) -> None:
    requested = (build_type or "").lower().strip()
    if requested and requested not in {"debug", "release"}:
        raise click.ClickException("build_type must be 'debug' or 'release'")

    # All artifacts are collected under "report/"
    report_root = Path(g.script_directory) / "report"
    report_unit_output = "report/unittest"          # gtest xml dir
    coverage_output = "report/coverage"              # gcovr html dir
    cppcheck_output = "report/cppcheck"              # cppcheck html dir
    _san_short = {"address": "asan", "thread": "tsan", "undefined": "ubsan"}.get(sanitizer, sanitizer)
    sanitizer_output = f"report/{_san_short}" if sanitizer != "off" else None  # sanitizer logs dir

    build_dir = resolve_build_dir(build_type)

    if not build_dir.is_dir():
        build_type_for_message = requested or "release"
        raise click.ClickException(
            f"Build directory not found: {build_dir}\n"
            f"Run: python3 raisin.py build --type {build_type_for_message}"
        )

    # Run cppcheck first
    if cppcheck:
        from commands.cppcheck import run_cppcheck
        from commands.utils import get_build_jobs
        click.echo("🔎 Running cppcheck static analysis...")
        run_cppcheck(build_type, jobs=get_build_jobs(), strict=False, report_dir=cppcheck_output)

    executables = _discover_tests(build_dir, suffixes)

    if not executables:
        raise click.ClickException(
            f"No test executables found under: {build_dir}\n"
            f"Expected files whose name ends with one of: {', '.join(suffixes)}."
        )

    sanitizer = (sanitizer or "off").lower()

    # Pick which executables to run: --package wins; otherwise a sanitizer run
    # auto-restricts to binaries actually built with the sanitizer (skips
    # uninstrumented ones, which can SEGV at startup under preload).
    if packages:
        wanted = [p.lower() for p in packages]
        selected = [e for e in executables if _pkg_matches(e, build_dir, wanted)]
        if not selected:
            raise click.ClickException(
                f"No test executables match --package {', '.join(packages)} under: {build_dir}"
            )
        skipped = len(executables) - len(selected)
        click.echo(f"📦 Package filter: {len(selected)} selected, {skipped} skipped.")
        executables = selected
    elif sanitizer != "off":
        if shutil.which("readelf") is None:
            click.echo("⚠️  readelf not found; cannot auto-scope to instrumented binaries.", err=True)
        else:
            instrumented = [e for e in executables if san.binary_is_instrumented(e, sanitizer)]
            skipped = len(executables) - len(instrumented)
            if instrumented:
                click.echo(
                    f"🧷 Sanitizer scope: {len(instrumented)} instrumented binary(ies); "
                    f"skipping {skipped} uninstrumented (pass --package to override)."
                )
                executables = instrumented
            else:
                # Nothing was built with the sanitizer -- stop with a clear
                # message instead of running the whole suite for nothing.
                bt = requested or "release"
                flag = san.SAN_FLAG.get(sanitizer, "--asan")
                raise click.ClickException(
                    f"{flag} ({sanitizer}) was requested but no instrumented test "
                    f"binaries were found under: {build_dir}\n"
                    f"This build was not configured with the sanitizer. Build it first, "
                    f"matching the build type you test:\n"
                    f"  raisin build -t {bt} {flag}\n"
                    f"  raisin test {bt} {flag}\n"
                    f"(No build type defaults to the release build dir; pass 'debug' to "
                    f"target the debug build.)"
                )

    suffix_names = {UNIT_SUFFIX: "unit", INTEGRATION_SUFFIX: "integration"}
    kinds = " + ".join(suffix_names.get(s, s.lstrip("_")) for s in suffixes)
    click.echo(f"🧪 Running {len(executables)} {kinds} test(s) in {build_dir}")

    if sanitizer != "off":
        san.apply_env(sanitizer)
        click.echo(f"🧷 Sanitizer mode: {sanitizer}")
        # The ASan runtime must load first; preload it so uninstrumented test
        # binaries that link the instrumented .so don't abort at startup.
        preload = san.resolve_runtime(build_dir, sanitizer)
        if preload:
            existing = os.environ.get("LD_PRELOAD", "")
            os.environ["LD_PRELOAD"] = ":".join(preload + ([existing] if existing else []))
            click.echo(f"🧷 LD_PRELOAD={os.environ['LD_PRELOAD']}")
        elif sanitizer in ("address", "undefined"):
            click.echo(
                f"⚠️  Could not locate the {sanitizer} runtime to preload; "
                "uninstrumented binaries linking the instrumented library may abort.",
                err=True,
            )

    # Capture sanitizer diagnostics to report/<asan|tsan|ubsan>
    san_dir = None
    san_entries = []
    if sanitizer != "off":
        san_path = Path(sanitizer_output)
        if not san_path.is_absolute():
            san_path = Path(g.script_directory) / san_path
        if san_path.is_dir():
            shutil.rmtree(san_path)
        san_dir = _resolve_output_dir(sanitizer_output)
        click.echo(f"🧷 Sanitizer report dir: {san_dir}")

    # The unit pass/fail report is produced only for a normal run. A sanitizer
    # run aborts each binary on the first error, so its counts are meaningless:
    # we skip the gtest XML and emit only the sanitizer report (report/<mode>.md).
    results = []
    xml_dir = None
    if sanitizer == "off":
        report_path = _resolve_output_dir(report_unit_output)
        xml_dir = report_path / "xml"
        if xml_dir.is_dir():
            shutil.rmtree(xml_dir)
        xml_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    for exe in executables:
        click.echo(f"\n▶ {exe}")
        # TSan's shadow-memory mapping requires ASLR disabled; launch via setarch -R.
        cmd = ["setarch", "-R", str(exe)] if sanitizer == "thread" else [str(exe)]
        label = _pkg_label_for_exe(exe, build_dir)
        xml_file = None
        if xml_dir is not None:
            xml_file = xml_dir / f"{label}__{exe.stem}.xml"
            cmd.append(f"--gtest_output=xml:{xml_file}")
        san_log = None
        if san_dir is not None:
            san_log = san_dir / f"{label}__{exe.stem}.log"
            san_entries.append({"label": label, "exe": exe, "prefix": san_log})
        status = "pass"
        try:
            # timeout=0 disables the limit; otherwise a hung test is killed
            # (SIGKILL) after `timeout` seconds, marked failed, and we move on.
            if san_log is not None:
                rc = san.run_streaming_capture(cmd, build_dir, timeout, san_log)
                if rc != 0:
                    raise subprocess.CalledProcessError(rc, cmd)
            else:
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
        results.append({"label": label, "status": status, "xml": xml_file})
        # Keep only sanitizer logs with reportable (PROJECT/CRASH) findings;
        # clean or SYSTEM-only logs are dropped.
        if san_log is not None and san_log.is_file() \
                and not san.log_has_reportable_findings(san_log, Path(g.script_directory)):
            san_log.unlink()

    # Normal run: print the pass/fail table and write report/unittest.md. A
    # sanitizer run produces no unit-test result -- only the sanitizer report.
    if sanitizer == "off":
        if failures:
            click.echo(f"\n⚠️  {failures} test(s) failed.", err=True)
        else:
            click.echo("\n✅ All tests passed.")
        agg = _aggregate_test_results(results)
        _print_test_table(agg)
        click.echo(f"\n📝 Test report: {_write_test_report_md(report_root / 'unittest.md', agg)}")

    if san_dir is not None:
        summary = san.summarize_logs(san_dir, san_entries, sanitizer)
        n_logs = len([p for p in san_dir.glob("*.log") if p.is_file()])
        click.echo(f"\n🧷 Sanitizer report: {summary}")
        if n_logs == 0:
            click.echo("   No sanitizer findings recorded (all instrumented binaries clean).")

    # Generate the coverage report even if some tests failed, so partial
    # coverage is still available. Done before raising on failures.
    if coverage:
        _generate_coverage_report_per_module(build_dir, coverage_output)

    if failures:
        if sanitizer == "off":
            raise click.ClickException(f"{failures} test(s) failed.")
        raise click.ClickException(
            f"{failures} binary(ies) aborted under the sanitizer "
            f"(see report/{_san_short}.md)."
        )


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
    "--coverage",
    is_flag=True,
    default=False,
    help="Also generate an HTML line-coverage report (gcovr) per package/module "
    "under report/coverage/, plus a landing page. Requires a build configured with "
    "-DRAISIN_BUILD_TEST=ON (Linux/gcc).",
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
    "--asan", is_flag=True, default=False,
    help="Run under AddressSanitizer + UBSan (build with 'raisin build --asan'). "
    "Covers undefined-behavior checks too. Only binaries actually built with the "
    "sanitizer are run, unless --package is given.",
)
@click.option(
    "--tsan", is_flag=True, default=False,
    help="Run under ThreadSanitizer (build with 'raisin build --tsan'); each "
    "binary is launched under 'setarch -R' (ASLR off).",
)
@click.option(
    "--cppcheck",
    is_flag=True,
    default=False,
    help="Also run cppcheck static analysis on the build (writes report/cppcheck/), "
    "after the tests. Same engine as 'raisin cppcheck'.",
)
@click.option(
    "--package",
    "-p",
    "packages",
    multiple=True,
    help="Only run tests of the named package(s) (e.g. -p raisin_parameter). May be "
    "repeated. Matches the package directory name.",
)
def test_command(
    build_type: Optional[str],
    only_unit: bool,
    only_integration: bool,
    coverage: bool,
    timeout: int,
    asan: bool,
    tsan: bool,
    cppcheck: bool,
    packages: tuple,
) -> None:
    """
    Run tests from the CMake build folder.

    By default runs BOTH unit (*_unittest) and integration (*_inttest) tests,
    unit first. Use --unit or --integration to run only one kind. The per-package
    pass/fail report (report/unittest/report.md) is always produced. All artifacts
    are collected under report/ (report/unittest, report/coverage, report/cppcheck,
    report/sanitizer-<mode>).

    \b
    Examples:
        raisin test debug                 # unit + integration (debug)
        raisin test debug --unit          # unit tests only
        raisin test debug --integration   # integration tests only
        raisin test debug --coverage      # + per-module coverage report
        raisin test debug --cppcheck      # + cppcheck static analysis
        raisin test debug --asan          # tests under ASan+UBSan
        raisin test debug --tsan          # tests under ThreadSanitizer
        raisin test debug -p raisin_parameter   # only one package's tests

    """
    if only_unit and only_integration:
        raise click.ClickException("--unit and --integration are mutually exclusive")

    # The sanitizer flags map to a single mode and are mutually exclusive
    # (ASan and TSan cannot be combined). --asan already includes UBSan checks.
    if asan and tsan:
        raise click.ClickException("--asan and --tsan are mutually exclusive")
    sanitizer = "address" if asan else "thread" if tsan else "off"

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
            coverage=coverage,
            timeout=timeout,
            sanitizer=sanitizer,
            packages=packages,
            cppcheck=cppcheck,
        )
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e)) from e
