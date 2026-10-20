# Opt-in desired-state-only archive selection

## Why

Developer CLI callers can deliberately pin an archive or fall back to legacy
tag/latest lookup with user credentials. Automatic fleet preparation must not
inherit those choices when the server has halted the node or has no usable
assignment. The opt-in restriction preserves existing CLI defaults rather than
changing selection policy for every caller.

## API and failure behavior

`download_all_from_archive(..., *, require_desired_state=False)` accepts an exact
`bool`. Omission or `False` preserves existing operator-pin, tag/latest and
user-credential fallback behavior.

With `True`:

- Explicit archive name/version pins and a nonempty `RAISIN_ARCHIVE_NAME` are
  rejected with `ValueError` before tree preparation. Invalid flag types also
  raise `ValueError` before tree preparation.
- The existing desired-state resolver must return a usable archive name/version
  and inline manifest. No legacy tag/latest/user-manifest fallback is allowed.
- Fleet halt raises `OtaInstallHalted`. Missing/unusable desired state or a
  resolver refusal raises `OtaDesiredStateUnusable`.
- Once selection succeeds, package schema/download/preparation failures retain
  the existing empty-dict result. That is failure, not permission to retry via
  a legacy selection path.

The existing resolver, package transaction, transport and extraction remain in
use. The option neither rewrites the global context/environment nor provides
another credential or loader.

## Write and authorization boundary

This flag restricts selection only. It does not authorize mutation, freeze the
fleet assignment, stop a runtime or isolate writes. `ensure_tree` still runs on
the caller's supplied release/install path before desired-state resolution
(except the early invalid-option/pin refusals above).

Private preparation must supply both a private release/install path and a
[private transaction cache](ota-transaction-download-cache.md), retaining
install-state exclusion through later descriptor use. Existing core session/event
state is not redirected. The caller must recheck its target/policy, matching
claim and fresh drain requirements before any live mutation. A successful
preparation result alone is not start or promotion authority.

Review history and verification evidence are recorded in
[raisin_master #127](https://github.com/raionrobotics/raisin_master/pull/127).
