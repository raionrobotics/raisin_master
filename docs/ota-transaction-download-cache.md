# OTA transaction download cache

## Why

A private install path alone does not isolate downloads: the default ZIP cache
is the configured workspace's `install/`. A transaction-specific destination lets
preparation keep downloads outside that live workspace location without changing
the configured context, authentication or session reporting.

## API and scope

`PackageInstallTransaction(install_base_path, *, upgrade=False,
download_cache_dir=None)` accepts an optional caller-controlled cache directory.
Omission or `None` keeps the configured workspace's `install/`. Construction does
not access that context or create directories; transport creates directories
lazily when a download is needed.

The selected cache applies to package downloads made through that transaction,
including:

- `download_package` and transactional `download_all_from_archive`, including
  alias/missing-tag ZIP prefetches used to determine the package version;
- `download_package_at_timestamp`, including a manifest without a version;
- partial bodies (`.zip.part`) and their digest/resume state (`.zip.part.json`).

These paths share the internal `_ota_zip_path(cache_dir, name, key)` calculation.
It chooses a location only; it does not create directories or grant isolation.
Nontransactional archive calls retain the workspace default. Standalone package
and timestamp calls create a default transaction and retain that same default.
There is no new global setting or nontransactional cache override.

An unusable explicit cache fails through the existing download failure handling;
it never falls back to the workspace cache. Authentication, session/event state,
platform selection, digest verification, retry and resume behavior are unchanged.

## Ownership and lifecycle

Use a stable, caller-owned path and retain existing install-state exclusion.
For private preparation the caller must supply an exclusively owned private
absolute path. The API does not validate ownership/ACLs, create a `0700` security
boundary, reserve a directory or defend against concurrent filesystem writers.

Successful extraction consumes its ZIP. Interrupted partials may remain for
resume; transaction exit does not promise cache garbage collection. The caller
owns cleanup, including prefetched candidates that were not selected.

The cache option does not redirect or defer install-tree preparation, freeze an
assignment, stop services, or authorize live writes. Use a private install path
as well, and apply [desired-state-only selection](ota-desired-only-selection.md)
when preparation must not inherit CLI fallback policy.

Review history and verification evidence are recorded in
[raisin_master #127](https://github.com/raionrobotics/raisin_master/pull/127).
