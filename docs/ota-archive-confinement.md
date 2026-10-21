# OTA ZIP extraction safety

## Why

ZIP extraction normalizes member names, but restoring permissions using the raw
names can affect files outside the extraction directory. A verified content hash
does not make member names safe. Client extraction and build-machine fetch share
`raisin_ota.archive_safety` so extraction and permission restoration agree on names.

## Contract

- Validate the complete member-name set before extraction or client old-package
  deletion. Reject absolute, parent-traversal, drive, backslash, NUL/control and
  normalized duplicate names. Ordinary dot prefixes remain supported. Windows
  additionally rejects reserved names, invalid filename characters and trailing
  dots/spaces.
- Builder extraction validates existing targets before writing: symlink,
  hardlink, reparse-point and special-node aliases are refused. An extraction
  root that is itself a symlink/reparse point is deliberately refused, not
  silently resolved to another destination.
- Permission restoration validates all member targets before changing modes.
  On supported POSIX platforms it uses nofollow directory/file descriptors and
  verifies regular single-link files before `fchmod`. An owned writable but
  unreadable file may use a write-only descriptor, without truncation or writes.
- Other platforms retain path-based chmod after name/physical-alias validation.
  Publisher file modes are masked to `0755`; directory modes are not restored.
- Ordinary per-file mode I/O errors warn and continue, preserving the existing
  best-effort contract. Name/type/alias violations are fatal. Client extraction
  returns `None` on refusal; the builder reports `FetchRefused`.
- Existing client imports of `restore_modes` and `PERMITTED_MODE` remain valid.

## Required caller boundary and non-goals

Callers must own a stable destination hierarchy and exclude concurrent writers.
This is not a sandbox against another process changing the filesystem. Validation
does not inspect every ancestor above the supplied root; it does not establish
whole legacy install-tree confinement or authorize deletion of an arbitrary
caller-supplied destination.

These checks do not redirect ZIP caches, make preparation private, stop a
runtime, or authorize promotion. Private preparation also needs a private install
path, a [private transaction cache](ota-transaction-download-cache.md), existing
install-state exclusion and the caller's mutation/start policy.

Review history and verification evidence are recorded in
[raisin_master #127](https://github.com/raionrobotics/raisin_master/pull/127).
