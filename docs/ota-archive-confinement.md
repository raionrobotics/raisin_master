# OTA ZIP extraction confinement checkpoint

Local candidate, 2026-10-19. Base is official raionrobotics upstream main
`f0338ab75002b7a53953691a85375c4606a5d20a`. No tag, published package, agent
dependency pin, installed service or device was changed.

## Why this changed

During managed-update preparation design, core-v0.1.8 was reproduced changing a
temporary sibling file's mode0700->0600 for absolute and parent-traversal ZIP
members. `extractall` normalizes those names, but old `restore_modes` used the
original name for chmod. A valid `release.yaml` and successful strict extraction
did not prevent the external permission effect. The same code remains in the
upstream base. Hash verification is not a filename-safety boundary.

Robot/client extraction and build-machine fetch now share `archive_safety`:

- Validate the whole ZIP name set before extraction or old-package deletion.
  Refuse absolute/parent/drive/backslash paths, NUL/control characters and
  normalized duplicate names; Windows additionally refuses reserved/normalized
  aliases. Ordinary dot prefixes remain supported.
- Builder extraction refuses existing symlink/hardlink/special-node aliases.
  Windows reparse-point metadata is treated as an alias.
- POSIX mode restoration opens nofollow directory/file FDs, verifies regular
  single-link files and fchmods only that FD. A writable-but-unreadable file may
  use an O_WRONLY FD without creation/truncation or a write.
- Other platforms keep their former path-based chmod after whole-set name and
  physical-alias validation. All extraction requires a caller-owned stable
  prefix; this is not a sandbox against concurrent malicious filesystem writers.
- Preserve the0755 ceiling, client `restore_modes`/`PERMITTED_MODE` imports and
  warning/continue behavior for ordinary per-file mode I/O failures. Alias/name
  violations remain fatal. Client returns None; builder raises FetchRefused.

At this ZIP-only checkpoint the cache-location prerequisite was NOT solved:
transactions still used the
configured workspace's `install/` for ZIP downloads. Private preparation needs a
separate reviewed cache destination and later dependency adoption before use.
Neither a private install_base_path nor these ZIP fixes authorize managed writes.
See the later [transaction cache candidate](ota-transaction-download-cache.md)
for the optional destination contract; private preparation remains open.

## Verification and review

Initial behavioral reproduction:14 FAIL/6 PASS. Special-node preflight added
RED3 and was corrected. Existing builder error-text assertion initially failed;
its `outside` contract was preserved without weakening the assertion.
Scoped fresh-context implementation review found three actionable issues:
DEL/C1 controls, mode-preflight I/O compatibility and a new read requirement for
chmod. The user chose internal correction; all were reproduced (RED7) and fixed.
Additional portability self-review reproduced5 failures for missing POSIX FDs/
Windows name normalization and corrected them. Windows branches are simulated
on Linux, not actual Windows execution. No additional independent post-fix
approval or external-model execution is implied.

Final results against this candidate:

- Python3.12 core suite:766 PASS,36 existing environment-dependent skips,12.06s.
  Skips require SDK/source sibling checkouts or an explicitly configured OTA
  server/robot credential. No tests/assertions/skip conditions were weakened.
- ZIP focused suite35 PASS,0 skips; same35 PASS in an isolated root container
  (0.20s), including a real UID2001 child for unreadable-file permissions.
- Agent suite using this changed core via PYTHONPATH:1201 PASS,0 skips,7.53s.
  The agent's declared core-v0.1.8 pin is still unchanged.
- Absolute-path guard mutation detected2 FAIL/28 deselected,0.07s, then restored
  in `finally` before final suite/container runs. No mutant commit or deployment.
- Python3.9 runtime smoke could not import core because that interpreter lacks
  requests; no host dependency installation was performed. Full3.9 and actual
  Windows execution remain unverified, not counted as passing.

Commands (from candidate core unless noted):

```sh
env PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -rs --tb=short -p no:cacheprovider
env PYTHONDONTWRITEBYTECODE=1 python3 -m pytest test_archive_safety.py -q --tb=short -p no:cacheprovider
# From the owned agent worktree; this is a local compatibility composition only:
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/path/to/core-candidate python3 -m pytest tests/ -q --tb=short -p no:cacheprovider
```

Container image: `raion-agent-runtime-start-model:20261019`,
SHA256`fb1debb5d2d3ecf204abe3a130b0dae1f0fc53bb511da0032044605afb9ce690`.
Network none, read-only rootfs/source mount, private/tmp tmpfs, all capabilities
dropped except CHOWN/DAC_OVERRIDE/SETUID/SETGID for fixture ownership and child
identity. No host bus/cgroup/credential/socket/device mounts. Ordinary core tests
also use disposable loopback HTTP fixtures; no production/device API was used.

Final `archive_safety.py` SHA256:
`b8a3d85f42eabc954a614762fb77a0ef886c419d22c0d1f178dcc517a7802594`.

The repository's shared pre-commit hook initially found no local configuration
in this new worktree. The original checkout's excluded config/baseline were
copied byte-for-byte locally, not changed or staged. Existing checks remained
enabled. Black formatted the changed files; private-key and secret detection
passed. Functional suites were rerun after formatting, not bypassed.

Primary behavior: [Python3.9 ZIP name normalization](https://docs.python.org/3.9/library/zipfile.html#zipfile.ZipFile.extract),
[descriptor-relative OS operations](https://docs.python.org/3.9/library/os.html#os.open).
