# Populate an owned marked runtime prefix

Candidate library mechanism on corePR13137ea05f; no CLI/agent factory or installed
activation. Existing `assemble`, `deploy_packages`, setup and legacy resource
behavior are unchanged. The caller still owns core exclusion, original operation
claim, fresh writer drain, verified candidate/current request/root completion and
the actual prefix lifetime. This API does not establish those authorities, issue
unit commands, release claims, remove markers or report runtime health.

## Interface

`runtime_prefix.populate_marked(context, *, selected_path, prefix, build_type, home)
-> List[Path]`

Require explicit canonical absolute real paths: context.workspace, selected_path,
prefix and device home. Selected_path is the exact caller-selected generation,
not the mutable release/install selector. It must be below the workspace's real
release/versions, with one direct real package directory per delivered package
and an optional empty regular `.staging` generation marker. No other files at
that level. The library does not select or validate generation numbers or infer
archive/authentication/installation identity from this path.

Validate platform components via the existing safe-component rules; build_type
is exactly debug or release. Every package must contain the requested exact
platform/build directory; missing/empty selection refuses before a prefix write.
Only that build is copied. Unselected build payloads are not traversed/copied.
Package order is lexical and later packages win on colliding regular file names,
matching the legacy merge model with an explicit deterministic ordering.
Overlays are also applied in lexical package order, after all package copies and
their permission normalization. Internal copy traversal and exact partial output
on a failure are not promised deterministic; only merge precedence and retained
negative state are. No caller may adopt that partial output as a resumable result.

Prefix is exactly workspace/install, already owned by the caller's effective
UID/GID, real0700 and ACL-free. It initially contains only one `.incomplete`:
an empty regular0600 single-link file with the same owner and no ACL. Never create,
delete, rename, chmod, copy metadata onto or replace that root/marker. Copy package
children, not the source root via copytree. Prefix dev/inode/mode/owner and full
marker metadata must remain the original facts; parent directory namespace
timestamps/nlink can change from adding children. Result paths are information
about the package inputs used, never completion/start/recovery authority.

## Input plan and failure behavior

Plan all selected package children and `home/.raisin/<package>/resource` overlays
before the first output write. Optional missing .raisin or resource directories
are fine; ordinary unrelated regular files immediately in .raisin are ignored.
Overlay discovery is one package level only. Overrides follow all packages and
retain the existing resource/<package>/resource destination layout, including
packages which have no delivered resource folder. Directory/file merge conflicts
raise, never yield a partially successful result. Output may remain partial.

All traversed input ancestors/entries must be real canonical directories or
single-link regular files, no symlink/special file/ACL. The selected generation
may carry only the checked optional marker plus packages. Reject any selected
build root child named .incomplete before writing; overlays are confined below resource.
Input trees and prefix must be disjoint. Count every inspected discovery/traversal
entry globally within each complete input plan, including ignored regular .raisin
entries and package directories without a resource, with a65536 cap. The post-copy
plan has its own identical cap. Stop enumeration immediately at the cap;
use iterative scans, not an unbounded recursive validation. Reject
unsupported ACL capability rather than assuming no ACL. This supported POSIX
managed profile does not expand legacy CLI platform requirements.

Retain metadata observations (excluding read-induced atime), repeat the input
plan after copying and permission normalization, and refuse if it changed. Normal
stable cooperative hierarchy, caller exclusion and trusted root/updater/mount
management are required; this is not a hostile same-UID/path-swap sandbox or a
content hash. The caller must not treat metadata observations as authentication.

The input profile intentionally requires the agent's freshly extracted complete
archive candidate (private_preparation), which already rejects hardlinks. It does
not accept legacy stage_version clones of unchanged packages: those use shared
inodes with st_nlink>1. That refusal is deliberate and will be tested with the
actual producer, not "fixed" by weakening the agent's existing preparation
contract. Legacy assemble/setup behavior for such generations is unchanged.

Mark copied bin files0755 and scripts/**/*.sh executable as the existing runtime
behavior does, but errors must propagate (no warning-and-continue in this path).
Do not use source/build discovery, generate compiler files, read CLI globals or
run external commands. Ordinary validation refusals use ValueError, I/O failures
propagate their OSError; internal programming errors/cancellation are not masked.
On every failure preserve original root/marker and retain partial output; no
rollback/deletion/repair/retry/recovery. Fresh independent whole validation and
strict file/directory synchronization remain the owner's later completion gate;
a returned list is not durable installation or successful startup.

## Required proof

Real filesystem copies with two packages/platforms/debug/release, deterministic
collisions, explicit generation despite a selector pointing elsewhere, leftover
src ignored, local resource overlays and root/marker identity preservation.
Refuse missing/nonempty/unsafe destination, missing package build, reserved marker
collision, symlinks/special files/hardlinks/ACLs, overlapping or changed inputs,
and entry-budget exhaustion before the first output write. Inject copy and chmod
failure/cancellation and confirm partial output stays marked, root/marker intact.
Mutation tests must detect deleting the marker, copying all builds or swallowing
permission errors. Preserve existing setup/assemble parity. Root/nonroot fixtures
do not prove installed guard/unit/PID1 or web→mission→web acceptance. No new core
release/dependency pin until separately reviewed immutable publication.

## Review and local verification, 2026-10-21

- Contract review found discovery-only entries were not included in the proposed
  bound. All inspected entries now share the per-plan budget, including ignored
  files and packages with no resource directory. Re-review found no required gap.
- Implementation review reproduced output scan PermissionError being swallowed
  by os.walk/rglob. Two RED regressions now pass with strict iterative scandir;
  the legacy helpers are unchanged. Corrective review also reproduced the exact
  `.sh` filename mismatch: two RED cases now pass with the existing glob semantics.
  No other required issue was found under the documented cooperative hierarchy.
- New managed tests:47, including actual legacy stage_version hardlink output,
  injected scan/copy/chmod failures, cancellation and original marker preservation.
  The chmod injection targets Path.chmod directly because pathlib3.9 caches its
  accessor; this is a test instrumentation difference, not a product fallback.
- Full host regression: Python3.9.25 **802 passed/36 skipped (11.90s)** and
  Python3.12.3 **802 passed/36 skipped (12.91s)**. Existing skips are20 SDK/source
  availability tests and16 external OTA server/robot credential tests. None were
  newly disabled. No external-server integration is claimed by this run.
- Restricted root and UID65534 fixtures each **71 passed (0.21s)**, including
  existing runtime-prefix/setup parity. Network disabled, read-only source/rootfs,
  private tmpfs, all capabilities dropped and no-new-privileges. No host services,
  state or credentials were mounted. Image sha256:
  `fb1debb5d2d3ecf204abe3a130b0dae1f0fc53bb511da0032044605afb9ce690`.
  Its absent CLI-only dependencies Click and Git were supplied by read-only mounts
  of the verified test environment's Click package and `/usr/bin/git`; initial
  missing-dependency runs are not counted as passing evidence.
- In-memory mutations of deleting the marker, copying both build types instead
  of the requested one, and omitting executable normalization were each detected
  by behavioral tests. Product callables were restored and source hashes unchanged.

Final product SHA256:
`8a95658f9878f1979e2214ca1db23ea314ca36a2ac3e4eadc4ffea67e5bed9aa`.
Final managed-test SHA256:
`ca93b43b89ad35841105c4562363b8c3c9903dffd5be91c480942bd456a9dc13`.

Replay from a checkout with declared dependencies and pytest installed:

```sh
python -m pytest -q -rs -p no:cacheprovider
python -m pytest test_managed_runtime_prefix.py test_runtime_prefix.py test_runtime_prefix_parity.py test_setup_deploy.py -q -p no:cacheprovider
```

This remains a reviewed opt-in library slice, not an installed owner, completed
runtime transition, PID1/power-loss proof or FMS command acceptance. No caller or
dependency pin is changed by this PR. The parent corePR131 still needs its own
review/merge and immutable publication before an agent adopts this mechanism.
