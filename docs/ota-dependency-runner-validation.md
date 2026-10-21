# Dependency runner exit-status regression and installation gap

2026-10-21; source base `ece29bf82c06d76706869e2d8417fed4ddaaa94c`.
Related: [merged #125](https://github.com/raionrobotics/raisin_master/pull/125),
agent [all-writer barrier #141](https://github.com/raionrobotics/raisin-ota-agent/pull/141).

## What is already fixed

Commit `f575d7ce227f13f0c7a5497bfa968d35a055367a` makes
`install_dependencies.sh` return 1 when any synchronous package installer fails.
Previously it printed a warning, then its final echo returned 0. The existing
agent accepts a successful unit start and can write its archive dependency stamp;
an aggregator that returns 0 after a package failure defeats that interpretation.
This PR adds regression evidence, not another implementation of the merged fix.

The latest source runner SHA256 is
`78729f25834c48f0e85fc7cf013543ce56dc5f534d6861039c7a26d52e94987b`.
The existing source-first provider and first-build-type behavior are preserved,
not proposed as the future managed dependency selection policy.

## Actual installed-state readback

Read-only SSH on `raion@192.168.10.100` found the workspace runner at
`/home/raion/raisin_ws/install_dependencies.sh` still at file-history commit
`3933cff684471b3fc6da586e4d587b0e82c17faf`, SHA256
`132744410140877b0a18957b3640e5f738bb811d699d70c364ed572f9429fa8c`.
Git reports no local change to this file. Its failure summary has no exit 1.
The dependency unit was inactive/dead, MainPID=0 and Job empty at readback.
These observations are not a held drain interval or proof that future work cannot
start. No installed script was run, changed, staged or restarted by this check.

Reading installed distribution metadata for published `raisin-ota==0.2.0`
confirms it does not contain this shell script. The package configuration includes
only `raisin_ota`, not the workspace tooling. Upgrading an agent/core wheel alone
therefore does not replace this installed workspace file. Do not mistake the
merged fix or a new agent version for proof of installed dependency behavior.

## Executed tests

`test_dependency_runner_exit.py` copies the real checked-in runner into a private
temporary workspace with spaces. Fake package scripts only write a marker and
exit with a chosen status. No sudo, package manager, network, device access or
installed workspace is used. Marker assertions require both source and release
fixtures to have actually executed; an empty lookup cannot masquerade as success.

- Original runner cases: 12 PASS. Source/release, executable/Bash fallback,
  success/failure, no installers, early failure followed by success, existing
  source precedence and invocation from another cwd.
- Independent source review found a test-fixture safety issue: absent os-release
  or VERSION_ID could build the wrong or absolute path. Fixed matching fallbacks
  and checked each component before joining. Nine additional contract tests
  began RED and now pass; scoped source re-review found no actionable defect.
  The reviewer did not independently execute the tests. Cross-model review was
  skipped during autonomous continuation; no external model CLI was executed.
- Final 21 PASS on Python3.9/3.12 and in root/UID65534 containers, each without
  network, capabilities or writable rootfs. Fixtures write only private tmpfs.
- Full core: Python3.9 **831 PASS/36 SKIP**, Python3.12 **831 PASS/36 SKIP**.
  The new file has zero skips on these Linux hosts. Existing SDK/server/credential
  environment skips are not acceptance proof for those integrations.
- Removing the unique exit 1 only from the temporary fixture input produced
  **7 FAIL/5 PASS**, and the original source remained unchanged. The same 12-case
  matrix using the exact read-only-fetched device script produced **7 FAIL/5 PASS**.
  These are local inert-package reproductions, not a dependency failure injected
  into the running robot. No assertion, skip or product behavior was weakened.
- Black check targets Python3.9; diff whitespace is checked. No remote CI or
  installed-PID1 result is implied by these local checks.

Replay from this checkout:

```sh
python -m pytest -q -p no:cacheprovider test_dependency_runner_exit.py
python -m pytest -q -p no:cacheprovider test_*.py
```

## Remaining managed-runtime boundary

Before managed dependency execution is enabled, provisioning must install and
verify the selected runner and effective unit inputs, not trust an old workspace
checkout or a unit name. Updating one script is not the entire completion contract:
the actual selected archive, fresh operation/attempt/invocation, successful
synchronous work and all-writer drain must agree. A stopped or force-killed partial
package installation is not successful completion or healthy apt state. Preserve
claims/evidence on uncertainty, and do not clear inhibition or start the runtime
from a historical dependency stamp alone.

No default updater path, systemd/polkit policy, credentials, channels, production
server or robot runtime is changed. This evidence does not complete FMS-M1's
authenticated web request -> nonphysical execution -> web result gate.
