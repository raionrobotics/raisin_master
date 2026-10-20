# Opt-in desired-state-only archive selection

Local candidate following core `daed0ba`; no tag/publication/dependency adoption.

`download_all_from_archive(..., *, require_desired_state=False)` adds an optional
selection restriction. Omission/False preserves existing CLI/operator-pin,
tag/latest and user-credential fallback behavior. The new flag must be bool.

True rejects explicit name/version pins and nonempty RAISIN_ARCHIVE_NAME before
tree repair, using ValueError for conflicting options. It requires desired-state
resolution with a usable name/version and inline manifest, without any legacy
tag/latest/user-manifest fallback. A fleet halt still raises OtaInstallHalted;
missing/unusable desired state raises OtaDesiredStateUnusable. The existing
resolver and real package transaction/transport/extraction remain in use.
Here “unusable desired state” means the selection/inline-manifest requirement or
a resolver refusal. Once selection succeeds, downstream package schema, download
and preparation failures keep their existing empty-dict result. That also stops
the private helper; neither outcome triggers legacy fallback.

This option does not confer authorization, freeze a fleet assignment, stop a
runtime, defer target-tree preparation or isolate writes by itself. As before,
ensure_tree runs on the caller's supplied release/install path before resolution.
Private preparation must supply a private release path AND a private transaction
download cache, hold the existing install-state exclusion and later recheck
policy/claim/drain before any live mutation. Existing core session/event state
outside live inputs is not redirected. No global env/context rewrite is used.

Reason: an unpinned private preparation caller otherwise inherits the existing
CLI fallbacks: ambient archive-name pins skip desired/halt, and a missing desired
assignment can select latest through user credentials. That is appropriate for
the existing developer CLI contract, but not for a caller requiring fleet-only
selection. Strengthen that caller without changing old callers' defaults.

## Verification and disposition

TDD: 18 failures/2 legacy controls before implementation, then 20 cases passed.
An additional case fixes the documented boundary between selection exceptions
and existing downstream package-preparation empty-dict results. Before that
test-only addition, whole core 794 PASS/36 existing environment skips (12.14s),
full candidate agent+mechanism+helper 1253 PASS/0 skips (8.10s), unchanged old-pin
agent 1201 PASS/0 skips (7.61s). Isolated strict-selection 20 PASS (0.09s), helper 41
PASS under root and UID65534 (0.19s each), network none/read-only source/rootfs/
all capabilities dropped. Existing core hooks passed after Black formatting;
functional suites ran on the formatted source. No test/skip/assertion weakening.

Pin-guard mutation caused 4 failures/16 deselected, then was restored in finally.
The agent duplicate-name mutation likewise caused 1 failure/40 deselected, restored
in finally. No mutant was committed or used outside temporary fixture paths.

Fresh independent review of the core/helper combination found no additional
substantive defect after the duplicate-name, ambient-pin and missing-desired
corrections. The downstream-result ambiguity was clarified above and tested,
not used to alter old failure behavior. The user selected internal finalization;
no external model ran. This is local candidate verification, not publication,
dependency adoption, factory activation or installed-device acceptance.

Final boundary-test addition: whole core 795 PASS/36 unchanged environment skips
(11.77s); isolated strict-selection 21 PASS (0.09s). No functional source changed
after the corresponding agent 1253 result; the addition documents/tests the
existing downstream empty-dict convention.

Publication self-review, 2026-10-20: removed a redundant resolver condition after
the strict-mode archive-pin refusal, without changing either selection policy.
The flag deliberately accepts exact bool, not merely objects that present a
compatible class: `type(value) is bool` expresses that narrow API contract.
Invalid flag tests still assert refusal before any tree preparation.
