# Transaction-specific OTA download destination

Local candidate, 2026-10-19, following the ZIP confinement candidate `4531079`.
No tag, published package, agent dependency pin or installed service is changed.

## Contract

`PackageInstallTransaction(install_base_path, *, upgrade=False,
download_cache_dir=None)` accepts an optional caller-controlled cache directory.
Omitting it or passing `None` preserves the configured workspace's `install/`.
The constructor neither accesses the configured context nor creates directories.
The existing transport creates the cache lazily when a download is needed.

For that transaction, package ZIP downloads, ZIP-declared version prefetches,
partial bodies (`.zip.part`) and their digest state (`.zip.part.json`) use the
selected directory. This includes every package in a transactional
`download_all_from_archive` call. Authentication, session/event reporting and
platform selection continue to use the real configured context; it is not
temporarily reconfigured. Standalone and nontransactional callers keep their
existing default behavior.

Use a stable, caller-owned path and the existing install-state exclusion.
This API does not check ownership/ACLs, create a0700 security boundary, reserve
a directory, or defend against concurrent malicious filesystem writers.
The caller must supply a private absolute scratch path when isolation is
required. An invalid explicit directory fails through the existing download
error handling; there is no fallback to workspace/install.

Transport retry, hash verification, resume and extraction semantics are
unchanged. Successful extraction consumes its ZIP. Interrupted partials may
remain for resume; transaction exit does not promise cache garbage collection.
The caller owns the cache lifecycle, including candidates fetched but not
selected. Supplying a cache does not redirect or defer install-tree preparation
and does not authorize promotion, dependencies, service control or live writes.

## Verification checkpoint

`test_transaction_download_cache.py` runs real core archive transactions,
transport, version reading and ZIP extraction. HTTP responses and reporting are
replaced with local fixtures. Coverage includes tagged, alias and missing-tag
archives, a two-package archive, unchanged default/None destinations, lazy
construction, interrupted downloads and cross-transaction Range/If-Range resume,
an unusable explicit path, unchanged context/session selection, and no activation
on transaction exit.

Initial RED:7 failures,1 legacy control passed. After implementation:8 focused
cases passed. Whole core:774 passed,36 existing environment-dependent skips
(12.25s). Agent tests using this candidate through PYTHONPATH:1201 passed,
0 skips (7.70s). Reversing the destination-selection branch produced7 failures
and1 pass; the source was restored in `finally`. All applicable existing
pre-commit checks passed without changing the tested Python sources. The same8
focused cases passed in the existing Ubuntu24 container with network disabled,
read-only source/rootfs, private/tmp and all capabilities dropped (0.09s).
These are not an installed-device acceptance claim.

An independent scoped implementation review found no substantive introduced
defect against this contract. The user chose internal continuation; no external
model ran. Rechecking the destination branch, transport companions, constructor
and existing callers against the contract found no unresolved blocker for this
local API slice. Private preparation, promotion and dependency adoption remain
separate open slices; this candidate does not complete I3c2a.

```sh
env PYTHONDONTWRITEBYTECODE=1 python3 -m pytest test_transaction_download_cache.py -q --tb=short -p no:cacheprovider
env PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q --tb=short -p no:cacheprovider
# From the owned agent worktree, local composition only:
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/path/to/core-candidate python3 -m pytest tests/ -q --tb=short -p no:cacheprovider
```
