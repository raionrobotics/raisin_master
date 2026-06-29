"""
Sanitizer (ASan/TSan/UBSan) support for `raisin test`.

Split out of commands.test to keep that module focused on discovering, running
and aggregating tests. Everything here is about making a sanitizer run work and
turning its diagnostics into a report:

  - apply_env / resolve_runtime  -- runtime options and LD_PRELOAD setup
  - binary_is_instrumented       -- pick only binaries built with the sanitizer
  - run_streaming_capture        -- tee a binary's output to console + log file
  - log_has_reportable_findings / summarize_logs -- parse logs into report/<mode>.md

These functions never call back into commands.test, so the dependency is
one-way (test -> sanitizer). echo/CLI handling stays in commands.test.
"""

import os
import re
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

from commands import globals as g


# Sanitizer mode <-> the short CLI flag that selects it on both build and test
# (e.g. `raisin build --asan` / `raisin test --asan`).
SAN_FLAG = {"address": "--asan", "thread": "--tsan", "undefined": "--ubsan"}

# DT_NEEDED soname fragments that mark a binary as built with each sanitizer
_SAN_SONAME_TOKENS = {
    "address": ("libasan", "libclang_rt.asan"),
    "undefined": ("libubsan", "libclang_rt.ubsan"),
    "thread": ("libtsan", "libclang_rt.tsan"),
}


def apply_env(sanitizer: str) -> None:
    """Set sanitizer runtime options (without overriding ones the user set)."""
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


def resolve_runtime(build_dir: Path, sanitizer: str) -> list:
    """Absolute paths of sanitizer runtimes to LD_PRELOAD, or [] if not needed."""
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


def binary_is_instrumented(exe: Path, sanitizer: str) -> bool:
    """True if exe was itself built with the sanitizer (runtime in its NEEDED).

    A -fsanitize=... binary lists the runtime in its own DT_NEEDED; one that
    just loads an instrumented .so does not, and we skip those. If we can't tell
    (no readelf, parse error) the binary is kept rather than dropped.
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


def run_streaming_capture(cmd, cwd, timeout, log_path: Path) -> int:
    """Run cmd, tee combined stdout+stderr to both the console and log_path.

    Used for sanitizer runs because GCC's UBSan prints to stderr instead of a
    log file, so we capture it ourselves. SIGKILLs the whole process group on
    timeout. Returns the exit code; raises subprocess.TimeoutExpired on timeout.
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
        except BaseException:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            t.join()
            raise
        t.join()
    return proc.returncode


def log_has_reportable_findings(log_path: Path, root: Path) -> bool:
    """True if the log has at least one finding we report (PROJECT/CRASH; SYSTEM
    is excluded). Used to drop logs that are clean or only system artifacts."""
    try:
        text = log_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    return bool(_parse_sanitizer_findings(text, root))


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
    """Parse a sanitizer log into findings, each pinned to a source location.

    Returns a list of dicts {kind, message, scope, location, trigger, frames}.
    `location` is the file:line to look at (the error line for UBSan, else the
    first project frame). Paths are made relative to root.
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
            # The error line's own location (UBSan has one; may be src or system).
            em = _SAN_LOC_RE.search(line)
            err_loc_any = f"{em.group(1)}:{em.group(2)}" if em else None
            err_in_project = bool(em and em.group(1).startswith(root_str)
                                  and "/cmake-build-" not in em.group(1))

            # Collect the backtrace, skipping ASan's intro lines before frame #0
            # and stopping once the frames end.
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
            # Scope: PROJECT = error at a src/ line (fix it); SYSTEM = error in a
            # system header (toolchain artifact); CRASH = signal, no source line.
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

    # Drop SYSTEM-scope findings: errors in system headers aren't project bugs.
    findings = [f for f in findings if f["scope"] != "SYSTEM"]

    # De-duplicate identical (scope, kind, location) findings within one binary.
    seen, uniq = set(), []
    for f in findings:
        key = (f["scope"], f["kind"], f["location"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def summarize_logs(san_dir: Path, entries: list, sanitizer: str) -> Path:
    """Scan per-binary sanitizer logs and write the summary .md; return its path.

    Clean binaries leave no log file (deleted after the run), so a missing log
    means "no findings". Each finding is listed with its source location.
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
        "- 🟠 **CRASH** — a signal (SEGV/abort) with no source line; see the trigger frame.",
        "",
        "_(SYSTEM-scope findings — UB inside system/3rd-party headers, e.g. the "
        "libstdc++ toolchain artifact — are excluded.)_",
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
        lines.append(f"raw log: `{san_dir.name}/{r['log']}`")
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

    # Top-level summary: report/asan.md or report/tsan.md (named after san_dir).
    path = san_dir.parent / f"{san_dir.name}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
