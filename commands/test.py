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
import signal
import subprocess
import sys
import threading
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


def _apply_sanitizer_env(sanitizer: str) -> None:
    """Set sanitizer runtime options (without clobbering user-provided ones).

    Sanitizers abort with a non-zero exit code on the first error, so the
    existing check=True run already counts a sanitizer hit as a test failure;
    these options just make the diagnostics louder and fail-fast.

    Leak detection defaults to OFF: only one package (the one whose CMakeLists
    calls raisin_enable_sanitizer) is instrumented, but `raisin test` runs the
    whole suite, and once the ASan runtime is preloaded (see
    _resolve_sanitizer_runtime) every binary -- including uninstrumented ones --
    runs LeakSanitizer at exit and reports leaks in code that was never meant to
    be leak-checked. That is noise, not a bug in the code under test. To leak-
    check the instrumented package, run its binary directly with
    ASAN_OPTIONS=detect_leaks=1.
    """
    defaults = {
        "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:halt_on_error=1:strict_string_checks=1",
        "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
        "TSAN_OPTIONS": "halt_on_error=1:second_deadlock_stack=1",
    }
    for key, value in defaults.items():
        os.environ.setdefault(key, value)


def _build_compiler(build_dir: Path) -> Optional[str]:
    """Return the C++ compiler this build dir was configured with (from cache)."""
    cache = build_dir / "CMakeCache.txt"
    if not cache.is_file():
        return None
    try:
        for line in cache.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("CMAKE_CXX_COMPILER:"):
                return line.split("=", 1)[1].strip()
    except Exception:
        return None
    return None


def _resolve_sanitizer_runtime(build_dir: Path, sanitizer: str) -> list:
    """Absolute paths of sanitizer runtimes to LD_PRELOAD, or [] if not needed.

    raisin_enable_sanitizer instruments a SHARED library (e.g. raisin_parameter)
    but not the many test executables that link it. ASan then aborts those
    executables at startup with "ASan runtime does not come first in initial
    library list", because libasan is pulled in only transitively via the .so.
    Preloading the runtime puts it first and lets the whole suite run. (TSan
    cannot be made to work via LD_PRELOAD, so 'thread' is excluded.)
    """
    if sanitizer not in ("address", "undefined"):
        return []
    cxx = _build_compiler(build_dir) or shutil.which("c++") or shutil.which("cc") or "cc"
    # gcc names first, then the clang runtime equivalents.
    if sanitizer == "address":
        candidates = ["libasan.so", "libclang_rt.asan-x86_64.so"]
    else:
        candidates = ["libubsan.so", "libclang_rt.ubsan_standalone-x86_64.so"]
    for name in candidates:
        try:
            out = subprocess.run(
                [cxx, f"-print-file-name={name}"],
                capture_output=True, text=True, check=False,
            ).stdout.strip()
        except Exception:
            continue
        # The compiler echoes the bare name back when it can't locate the lib.
        if out and out != name and Path(out).is_file():
            return [str(Path(out).resolve())]
    return []


def _pkg_matches(exe: Path, build_dir: Path, wanted_lower: list) -> bool:
    """True if exe belongs to one of the requested packages (case-insensitive).

    Matches either the package label (the package directory name) or any path
    component, so '-p raisin_parameter' selects src/raisin/raisin_parameter/*.
    """
    label = _pkg_label_for_exe(exe, build_dir).lower()
    parts = [p.lower() for p in exe.relative_to(build_dir).parts]
    return any(w == label or w in parts for w in wanted_lower)


# DT_NEEDED soname fragments that mark a binary as built with each sanitizer
# (gcc names first, then the clang runtime equivalents).
_SAN_SONAME_TOKENS = {
    "address": ("libasan", "libclang_rt.asan"),
    "undefined": ("libubsan", "libclang_rt.ubsan"),
    "thread": ("libtsan", "libclang_rt.tsan"),
}

# Sanitizer mode <-> the short CLI flag that selects it (test side) and the
# value the build side takes via `raisin build --test <mode>`.
_SAN_FLAG = {"address": "--asan", "thread": "--tsan", "undefined": "--ubsan"}


def _binary_is_instrumented(exe: Path, sanitizer: str) -> bool:
    """True if exe itself was linked with the sanitizer runtime (its own NEEDED).

    A binary compiled with -fsanitize=... lists the runtime among its own
    DT_NEEDED entries. A binary that merely loads an instrumented .so pulls the
    runtime in only transitively and is NOT treated as instrumented here -- that
    is exactly the set we want to skip, since preloading the runtime into an
    uninstrumented binary can destabilize it. On any uncertainty (no readelf,
    parse error) the binary is kept rather than silently dropped.
    """
    tokens = _SAN_SONAME_TOKENS.get(sanitizer)
    if not tokens:
        return True
    try:
        out = subprocess.run(
            ["readelf", "-d", str(exe)], capture_output=True, text=True, check=False
        ).stdout
    except Exception:
        return True
    for line in out.splitlines():
        if "(NEEDED)" in line and any(t in line for t in tokens):
            return True
    return False


def _run_streaming_capture(cmd, cwd, timeout, log_path: Path) -> int:
    """Run cmd, tee combined stdout+stderr to both the console and log_path.

    Used for sanitizer runs so diagnostics are captured to a file reliably --
    GCC's UBSan ignores its log_path option and prints to stderr, so we can't
    rely on the sanitizers writing files themselves. Streams live (chunked) and
    SIGKILLs the whole process group on timeout, matching the non-capturing path.
    Returns the process exit code; raises subprocess.TimeoutExpired on timeout.
    """
    with open(log_path, "wb") as f:
        proc = subprocess.Popen(
            cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        def pump():
            for chunk in iter(lambda: proc.stdout.read(4096), b""):
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                f.write(chunk)

        t = threading.Thread(target=pump)
        t.start()
        try:
            proc.wait(timeout=timeout if timeout and timeout > 0 else None)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            t.join()
            raise
        t.join()
    return proc.returncode


def _log_has_findings(log_path: Path) -> bool:
    try:
        text = log_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    return any(m in text for m in _SAN_FINDING_MARKERS)


# Lines that mark a genuine sanitizer diagnostic in a log file.
_SAN_FINDING_MARKERS = (
    "runtime error:",
    "ERROR: AddressSanitizer",
    "ERROR: LeakSanitizer",
    "ERROR: ThreadSanitizer",
    "ERROR: MemorySanitizer",
)

# A source file:line inside a stack frame or error line (excludes binary+offset
# frames, which end in "+0x...)" and have no ":<line>").
_SAN_LOC_RE = re.compile(r"(/[^\s():]+\.(?:cpp|cxx|cc|c|hpp|hxx|hh|h|tcc|ipp)):(\d+)")
# A backtrace frame:  "    #4 0x... in <func> <location-or-binary+offset>"
_SAN_FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.*)$")


def _san_kind(marker_line: str) -> str:
    """Short error kind, e.g. 'ASan: SEGV' or 'UBSan: load of invalid bool'."""
    if "runtime error:" in marker_line:
        reason = marker_line.split("runtime error:", 1)[1].strip()
        # keep it short
        return "UBSan: " + (reason[:60] + "…" if len(reason) > 60 else reason)
    m = re.search(r"ERROR:\s*(\w*Sanitizer):\s*(.*)", marker_line)
    if m:
        tool = m.group(1).replace("Sanitizer", "San")
        detail = m.group(2).split(" on ", 1)[0].split("(", 1)[0].strip()
        return f"{tool}: {detail}"[:70]
    return marker_line.strip()[:70]


def _parse_sanitizer_findings(text: str, root: Path) -> list:
    """Parse a sanitizer log into findings, each with the precise source site.

    Returns a list of dicts: {kind, message, location, in_project, frames}.
    `location` is the first project-source frame (path under `root`) — the line
    you actually need to look at — falling back to the error line's own location
    (UBSan) and then to '(no source frame)'. `frames` are the project-source
    frames, with paths made relative to root.
    """
    root_str = str(root)

    def rel(p):
        return p[len(root_str) + 1:] if p.startswith(root_str + "/") else p

    lines = text.splitlines()
    findings = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if any(m in line for m in _SAN_FINDING_MARKERS):
            message = line.strip()
            # location on the error line itself (UBSan always has one; it may be
            # in project src or in a system header).
            em = _SAN_LOC_RE.search(line)
            err_loc_any = f"{em.group(1)}:{em.group(2)}" if em else None
            err_in_project = bool(em and em.group(1).startswith(root_str)
                                  and "/cmake-build-" not in em.group(1))

            # Collect the backtrace. ASan prints intro lines ("The signal is
            # caused by...") between the error line and frame #0, so skip
            # non-frame lines until frames start; stop when the backtrace ends.
            proj_frames = []
            j = i + 1
            started = False
            while j < n:
                lj = lines[j]
                fm = _SAN_FRAME_RE.match(lj)
                if fm:
                    started = True
                    rest = fm.group(2)
                    lm = _SAN_LOC_RE.search(rest)
                    if lm and lm.group(1).startswith(root_str) and "/cmake-build-" not in lm.group(1):
                        func = rest[: lm.start()].strip().rstrip("(").strip()
                        proj_frames.append((fm.group(1), func, f"{lm.group(1)}:{lm.group(2)}"))
                    j += 1
                    continue
                if any(m in lj for m in _SAN_FINDING_MARKERS):
                    break          # next finding begins
                if started:
                    break          # backtrace ended
                j += 1             # still in the intro preamble; keep skipping

            first_proj = proj_frames[0][2] if proj_frames else None
            # Scope: PROJECT = UB at a src/ line (fix it); SYSTEM = UB inside a
            # system/3rd-party header (usually a toolchain/ABI artifact, not your
            # bug); CRASH = a signal with no source line (look at the trigger).
            if err_in_project:
                scope, location = "PROJECT", rel(err_loc_any)
            elif err_loc_any:
                scope, location = "SYSTEM", err_loc_any
            elif first_proj:
                scope, location = "CRASH", rel(first_proj)
            else:
                scope, location = "CRASH", "(no project source frame)"

            findings.append({
                "kind": _san_kind(message),
                "message": message,
                "scope": scope,
                "location": location,
                "trigger": rel(first_proj) if first_proj else None,
                "frames": [(nf, fn, rel(lc)) for (nf, fn, lc) in proj_frames[:6]],
            })
            i = j
            continue
        i += 1

    # de-duplicate identical (scope, kind, location) findings within one binary
    seen, uniq = set(), []
    for f in findings:
        key = (f["scope"], f["kind"], f["location"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def _summarize_sanitizer_logs(san_dir: Path, entries: list, sanitizer: str) -> Path:
    """Scan per-binary sanitizer log files and write summary.md; return its path.

    Empty/clean binaries leave no log file (deleted after the run), so their
    absence means "no findings". For each finding the report pins the precise
    source site (file:line) and flags whether it is in project code or only in
    system/3rd-party code (the latter is typically a toolchain artifact).
    """
    root = Path(g.script_directory)
    rows = []
    for e in entries:
        lf = e["prefix"]  # the per-binary .log (kept only if it had findings)
        if not lf.is_file():
            continue
        try:
            text = lf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        findings = _parse_sanitizer_findings(text, root)
        if findings:
            rows.append({"label": e["label"], "exe": str(e["exe"]),
                         "log": lf.name, "findings": findings})

    rows.sort(key=lambda r: r["label"])
    n_findings = sum(len(r["findings"]) for r in rows)

    scope_icon = {"PROJECT": "🔴 PROJECT", "SYSTEM": "⚪ SYSTEM", "CRASH": "🟠 CRASH"}
    n_project = sum(1 for r in rows for f in r["findings"] if f["scope"] == "PROJECT")

    lines = [
        f"# Sanitizer report ({sanitizer})",
        "",
        f"Binaries with findings: **{len(rows)}**  ·  total findings: **{n_findings}**  "
        f"·  🔴 PROJECT (fixable): **{n_project}**",
        "",
        "- 🔴 **PROJECT** — UB/error at a `src/` line. **This is your bug; fix it.**",
        "- ⚪ **SYSTEM** — error inside a system/3rd-party header (e.g. libstdc++). "
        "Usually a toolchain/ABI artifact, not your code; suppress.",
        "- 🟠 **CRASH** — a signal (SEGV/abort) with no source line; see the trigger frame.",
        "",
        "| Package | Scope | Location (file:line) | Kind |",
        "|---|---|---|---|",
    ]
    for r in rows:
        for f in r["findings"]:
            lines.append(
                f"| {r['label']} | {scope_icon.get(f['scope'], f['scope'])} "
                f"| `{f['location']}` | {f['kind']} |"
            )
    if not rows:
        lines.append("| _none_ | | | |")
    lines.append("")

    for r in rows:
        lines.append(f"## {Path(r['exe']).name}  (`{r['label']}`)")
        lines.append(f"raw log: `{r['log']}`")
        lines.append("")
        for f in r["findings"]:
            lines.append(f"- **[{f['scope']}] {f['kind']}**")
            lines.append(f"  - 📍 `{f['location']}`")
            if f["trigger"] and f["trigger"] != f["location"]:
                lines.append(f"  - triggered from: `{f['trigger']}`")
            lines.append(f"  - {f['message']}")
            if f["frames"]:
                lines.append("  - call path (project frames):")
                lines.append("    ```")
                for (nf, func, loc) in f["frames"]:
                    fn = (func[:70] + "…") if len(func) > 70 else func
                    lines.append(f"    #{nf} {fn}  {loc}")
                lines.append("    ```")
        lines.append("")

    path = san_dir / "summary.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


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

    # All artifacts are collected under report/ with fixed sub-directories.
    report_unit_output = "report/unittest"
    coverage_output = "report/coverage"
    cppcheck_output = "report/cppcheck"
    sanitizer_output = f"report/sanitizer-{sanitizer}" if sanitizer != "off" else None

    build_dir = _resolve_build_dir(build_type)

    if not build_dir.is_dir():
        build_type_for_message = requested or "release"
        raise click.ClickException(
            f"Build directory not found: {build_dir}\n"
            f"Run: python3 raisin.py build --type {build_type_for_message}"
        )

    # Static analysis (cppcheck) is independent of test execution, so run it
    # first -- results appear immediately and aren't blocked by slow/failing
    # tests. (Coverage stays after the run; it needs the gcda the tests emit.)
    if cppcheck:
        # Lazy import: commands.cppcheck imports from this module.
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

    # Scope which executables run (method B). An explicit --package always wins;
    # otherwise, in a sanitizer run, auto-restrict to binaries that were actually
    # built with the sanitizer. This avoids preloading the runtime into
    # uninstrumented binaries (which can cause spurious startup SEGVs) and skips
    # unrelated suites that the instrumented package never touches.
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
            click.echo(
                "⚠️  readelf not found; cannot auto-scope to instrumented binaries. "
                "Running the full suite (use --package to scope manually).",
                err=True,
            )
        else:
            instrumented = [e for e in executables if _binary_is_instrumented(e, sanitizer)]
            skipped = len(executables) - len(instrumented)
            if instrumented:
                click.echo(
                    f"🧷 Sanitizer scope: {len(instrumented)} instrumented binary(ies); "
                    f"skipping {skipped} uninstrumented (pass --package to override)."
                )
                executables = instrumented
            else:
                # Nothing here was built with the sanitizer. Running the whole
                # suite with the runtime preloaded is pointless (no instrumented
                # code to check) and slow/fragile, so stop with a clear message
                # rather than silently grinding through every binary.
                bt = requested or "release"
                flag = _SAN_FLAG.get(sanitizer, "--asan")
                raise click.ClickException(
                    f"{flag} ({sanitizer}) was requested but no instrumented test "
                    f"binaries were found under: {build_dir}\n"
                    f"This build was not configured with the sanitizer. Build it first, "
                    f"matching the build type you test:\n"
                    f"  raisin build -t {bt} --test {sanitizer}\n"
                    f"  raisin test {bt} {flag}\n"
                    f"(No build type defaults to the release build dir; pass 'debug' to "
                    f"target the debug build.)"
                )

    suffix_names = {UNIT_SUFFIX: "unit", INTEGRATION_SUFFIX: "integration"}
    kinds = " + ".join(suffix_names.get(s, s.lstrip("_")) for s in suffixes)
    click.echo(f"🧪 Running {len(executables)} {kinds} test(s) in {build_dir}")

    if sanitizer != "off":
        _apply_sanitizer_env(sanitizer)
        click.echo(f"🧷 Sanitizer mode: {sanitizer}")
        # The ASan runtime must load first; preload it so uninstrumented test
        # binaries that link the instrumented .so don't abort at startup.
        preload = _resolve_sanitizer_runtime(build_dir, sanitizer)
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

    # Capture sanitizer diagnostics to report/sanitizer-<mode>: each binary's
    # output is teed to a log file, and clean logs are dropped afterwards so only
    # binaries with findings remain, plus a summary.md.
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

    # The pass/fail report is always produced: each gtest binary emits JUnit XML
    # which is aggregated into report/unittest/report.md.
    results = []
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
                rc = _run_streaming_capture(cmd, build_dir, timeout, san_log)
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
        # Keep only sanitizer logs that actually contain findings.
        if san_log is not None and san_log.is_file() and not _log_has_findings(san_log):
            san_log.unlink()

    if failures:
        click.echo(f"\n⚠️  {failures} test(s) failed.", err=True)
    else:
        click.echo("\n✅ All tests passed.")

    agg = _aggregate_test_results(results)
    _print_test_table(agg)
    click.echo(f"\n📝 Test report: {_write_test_report_md(report_path, agg)}")

    if san_dir is not None:
        summary = _summarize_sanitizer_logs(san_dir, san_entries, sanitizer)
        n_files = len([p for p in san_dir.glob("*") if p.is_file() and p.name != "summary.md"])
        click.echo(f"\n🧷 Sanitizer report: {summary}")
        if n_files == 0:
            click.echo("   No sanitizer findings recorded (all instrumented binaries clean).")

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
    help="Run under AddressSanitizer+UBSan (build with 'raisin build --test address'). "
    "Only binaries actually built with the sanitizer are run, unless --package is given.",
)
@click.option(
    "--tsan", is_flag=True, default=False,
    help="Run under ThreadSanitizer (build with 'raisin build --test thread'); each "
    "binary is launched under 'setarch -R' (ASLR off).",
)
@click.option(
    "--ubsan", is_flag=True, default=False,
    help="Run under UndefinedBehaviorSanitizer (build with 'raisin build --test undefined').",
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
    ubsan: bool,
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
        raisin test debug --ubsan         # tests under UBSan
        raisin test debug -p raisin_parameter   # only one package's tests

    """
    if only_unit and only_integration:
        raise click.ClickException("--unit and --integration are mutually exclusive")

    # The sanitizer flags map to a single mode and are mutually exclusive
    # (ASan and TSan cannot be combined).
    selected = [name for name, on in
                (("address", asan), ("thread", tsan), ("undefined", ubsan)) if on]
    if len(selected) > 1:
        raise click.ClickException("--asan, --tsan and --ubsan are mutually exclusive")
    sanitizer = selected[0] if selected else "off"

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
