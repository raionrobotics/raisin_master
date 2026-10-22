# Populate an owned marked runtime prefix

This opt-in library mechanism does not activate an installed CLI or agent path.
Existing `assemble`, `deploy_packages`, setup and legacy resource behavior are
unchanged. The caller owns core exclusion, the original operation claim, fresh
writer drain, verified candidate/current request, root completion and actual
prefix lifetime. This API does not establish those authorities, issue unit
commands, release claims, remove markers or report runtime health.

## Interface

`runtime_prefix.populate_marked(context, *, selected_path, prefix, build_type, home)
-> List[Path]`

Require explicit canonical absolute real paths for context.workspace,
selected_path, prefix and device home. selected_path is the exact caller-selected
generation, not the mutable release/install selector. It must be directly below
the workspace's real release/versions, with one real package directory per
delivered package and an optional empty regular `.staging` generation marker.
No other files are allowed at that level. The library does not select or validate
generation numbers or infer archive/authentication/installation identity.

Validate platform components with the existing safe-component rules; build_type
is exactly debug or release. Every package must contain the requested exact
platform/build directory; missing/empty selection refuses before a prefix write.
Only that build is copied. Unselected build payloads are not traversed/copied.
Package order is lexical; later packages win on colliding regular file names.
Device overlays are applied in lexical package order after all package copies
and executable normalization. Internal copy traversal and exact partial output
on failure are not promised deterministic. Partial output is never resumable.

Prefix is exactly workspace/install, already owned by the caller's effective
UID/GID, real0700 and ACL-free. It initially contains only one `.incomplete`: an
empty regular0600 single-link file with the same owner and no ACL. Never create,
delete, rename, chmod, copy metadata onto or replace that root/marker. Copy package
children, not the source root via copytree. Prefix dev/inode/mode/owner and full
marker metadata must remain original. Parent namespace timestamps/nlink may change
as children are added. Returned package paths confer no completion/start authority.

## Input stability and bounded discovery

Plan all selected package children and home/.raisin/<package>/resource overlays
before the first output write. Missing .raisin/resource directories are allowed;
ordinary unrelated regular files immediately in .raisin are ignored. Discovery
is one package level only. Overrides retain resource/<package>/resource layout,
including packages without delivered resources. Directory/file conflicts raise.

All inspected entries must be real directories or single-link regular files,
without symlink/special file/extended ACL. Required ancestors must be canonical
real directories. Reject a selected build root child named `.incomplete` before
writing; overlays remain below resource. Input trees and prefix must be disjoint.
Unsupported ACL capability refuses rather than assuming no ACL.

Repeat the plan after copying and normalization. Full metadata observations,
excluding read-induced atime, must match for copied trees and the generation
marker. Selected generation membership must match. Required ancestors retain
dev/inode/mode/owner, but not size, nlink or namespace timestamps: unrelated files
added to home/workspace/release do not invalidate copied inputs. Ignored .raisin
files and resource-less packages are checked for safety and counted, not retained
as content witnesses. A newly discovered real overlay still changes the plan and
refuses. Stable cooperative hierarchy, caller exclusion and trusted root/updater/
mount management are required. This is metadata change detection, not content
authentication or a hostile same-UID/path-swap sandbox.

`MANAGED_PREFIX_MAX_ENTRIES` is 65,536. Each complete input plan counts unique
inspected paths, including required ancestors, ignored discovery entries and
optional missing resource paths. Re-inspection does not double-charge a path;
multiple metadata facts about it do not consume extra entries. Pre/post plans
have separate identical budgets; scans stop before inspecting an entry beyond
the limit. Executable traversal has a separate 65,536-entry bound. Scans are
iterative, not unbounded recursion.

The agent's private-preparation/output witness also has a 65,536 limit, but counts
one tree including its root, not this entire discovery set. These are distinct
sets: a prepared candidate can fit while population exceeds its discovery budget
because of ancestors or local overlays. No unlimited/future-release capacity is
promised. A caller must handle `entry_limit` as an incomplete refusal; never raise
the limit silently, truncate the plan or adopt partial output. The public constant
lets callers detect limit-profile drift before beginning owned work.

The managed profile requires freshly extracted complete single-link candidates.
Legacy stage_version clones share inodes with st_nlink>1 and are deliberately
refused. Legacy assemble/setup behavior for those generations is unchanged.

## Refusals and ownership

Managed validation raises `RuntimePrefixError`, a backwards-compatible ValueError
subclass with a fixed `reason_code`. Codes are invalid_input, unsafe_entry,
hardlinked_input, extended_acl, acl_unavailable, invalid_prefix, invalid_marker,
invalid_build, missing_build, no_packages, entry_limit, input_changed and
output_changed. Codes do not contain paths or original exception strings. An
ordinary ValueError from existing component validation need not have a code.
I/O errors propagate as OSError; programming errors/cancellation are not masked.
Consumers must allowlist codes at this boundary, not trust arbitrary exception
attributes elsewhere or parse raw error text.

Copied bin files become0755; scripts/**/*.sh gain executable bits. Copy/scan/chmod
errors propagate. Do not discover source/build trees, generate compiler files,
read CLI globals or run external commands. Every failure retains original
root/marker and any partial output, without deletion/rollback/repair/retry.
Fresh independent whole validation, strict file/directory synchronization and
explicit recovery remain the owner's later gate. A return is not durable
installation or successful startup. Immutable publication and separately reviewed
caller adoption are required before deployment.

## Verification and history

Run the managed and legacy-parity checks, then the full suite with declared
dependencies installed:

```sh
python -m pytest test_managed_runtime_prefix.py test_runtime_prefix.py test_runtime_prefix_parity.py test_setup_deploy.py -q -p no:cacheprovider
python -m pytest -q -rs -p no:cacheprovider
```

Coverage must include real copies, exact selected builds, collisions, overlays,
root/marker preservation, irrelevant namespace changes, changed copied inputs,
unsafe/overlapping inputs, exact budget boundaries and injected copy/scan/chmod
failure/cancellation. Local fixtures do not prove installed PID1/power-loss or
web→mission→web acceptance.

Historical verification counts, artifact hashes and environment details belong
to [PR #138](https://github.com/raionrobotics/raisin_master/pull/138), not the durable
contract. Earlier records remain inspectable in
[the pre-review documentation](https://github.com/raionrobotics/raisin_master/blob/15ab719b94122ab9e8d47773af0a607e8d1a8a9d/docs/ota-managed-prefix.md).
The [review](https://github.com/raionrobotics/raisin_master/pull/138#pullrequestreview-5609033203)
records the namespace, limit, diagnostics and documentation corrections.
