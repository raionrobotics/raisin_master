# Explicit delivered dependency selection

Status: implemented opt-in CLI candidate for
[setup#159](https://github.com/raionrobotics/raion-setup/issues/159); no installed caller.
Base: core PR136 `e761fb2`, preserving its exit-status regression and review.

## Contract

Add exactly one opt-in selector to the workspace runner:

```sh
bash install_dependencies.sh -y --delivered-build-type=release
```

Without that selector, preserve the old source-first, first available build-type
behavior and existing exit-status fix. Previously ignored legacy arguments stay
ignored when this new option is absent. The new option's own malformed spelling,
empty/unsafe value or duplicate occurrence must refuse with exit2 before any
installer. In explicit delivered mode, accept only this selector and existing -y;
unknown extra arguments also refuse before installers. Accept a single literal
build-type component of 1–64 ASCII alphanumeric/underscore/dot/hyphen characters,
starting with an alphanumeric character: no slash, whitespace or glob expansion.
Do not accept a path, command, environment override or alternate workspace root.

In explicit mode, never inspect or execute src/* installers. Require the script's
own workspace release/install directory to exist before package execution; a
missing/dangling selection is not successful no-work. For the detected host
OS/version/architecture, inspect only each package's exact requested build type.
Never fall back to another build type or the source provider. Packages with no
installer for the selected type contribute no work. Existing package error
aggregation remains: continue to collect failures, then exit1 if any failed.
An existing empty delivered directory or selected packages declaring no installer
returns0; this is no declared script work, NOT independently proven archive or
dependency readiness.

## Authority and limits

This is input selection only. The future root participant must independently
verify the effective unit/runner and actual selected immutable archive, preserve
the original core exclusion and operation claim, bind a new attempt/invocation,
and combine successful work with descendant-drain evidence. A CLI flag is not
authentication, a payload seal, a root-execution grant or a completion receipt.
The runner does not validate archive metadata/hashes, prevent filesystem races,
guarantee child synchronization or repair apt. Approved scripts and a stable
cooperating hierarchy remain required. No new root worker/default unit or
unprivileged caller is enabled by adding this option.

Do not route a managed request to the old unit merely because the old unit is
loaded or its start returns0. setup#159's installed runner/profile and fresh
completion gates remain open. FMS command permissions/transport are separately
awaiting user choice; this increment does not select or activate them.

## Verification plan

Run the real script with inert marker/exit package fixtures. Prove a conflicting
source provider is untouched, debug/release scripts cannot substitute for one
another, missing exact-type work does not fall back, malformed/duplicate/unknown
explicit options cause zero installer effects and missing selection refuses.
Exercise executable and Bash-fallback installers, failure aggregation, no-script
delivery and unchanged legacy source-first behavior. No sudo/apt/network/device
or actual system manager is needed or claimed for this selection boundary.

Use the existing Python3.9/3.12 core suite and restricted root/non-root containers.
Keep PR136's original tests green; mutation checks must detect accidental source
fallback or wildcard-build selection. Review source and contract before enabling
any installed participant. No production, device, credential, desired-state,
service/polkit change, tag/publication or FMS-M1 completion is included here.

## Executed evidence, 2026-10-21

Contract and implementation received separate read-only independent reviews;
neither found an actionable issue. Reviewers did not independently run tests.
Cross-model skipped for autonomous continuation; no external model CLI ran.

Initial new-interface tests: 25 RED /7 controls. Final new39 plus original22
runner cases: 61 PASS; restricted root and UID65534 containers61 PASS each.
Full core Python3.9:871 PASS/36 existing environment SKIP; Python3.12:871 PASS/36
existing environment SKIP. The two runner files have zero skips on these Linux
hosts. Existing SDK/server/credential skips are not integration acceptance.

Removing source exclusion only from temporary fixture input causes2 failures;
substituting wildcard build selection causes2 failures/1 control; removing name
validation causes16 failures. Each experiment restores the original Path reader
and verifies unchanged source bytes. Bash syntax, Python3.9-targeted Black and
diff whitespace checks pass. No remote CI, installed root unit or device proof
is inferred. Final runner SHA256:
`71cb54777d167b3668b321294257ba47ebf9b31f8f60b3a06f1d8cb30f1ddbe4`.
