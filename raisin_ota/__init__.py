"""The OTA mechanism: resolve a version, fetch it, verify it, install it atomically.

Deliberately has no opinion about *whether* it should be doing so right now.
That is policy, and it belongs to whatever calls this — the developer CLI, the
robot agent, or a commissioning tool. The mechanism is told who it is and where
it works via `configure()`; it never goes looking (see the design record,
`raisin-package-manager#71`).

This module exports the vocabulary — the context types and the failures a
caller has to distinguish. The operations live in the submodules:

    from raisin_ota import configure, OtaContext, RobotIdentity
    from raisin_ota import client, install_tree

Only `raisin_ota.ssh` needs `cryptography`, and only the user-authenticated
path reaches it, so it is an install extra rather than a dependency: a robot
authenticating with its own credential should not have to build a native
extension it will never call.
"""

from .client import (
    ContentHashMismatch,
    OtaContext,
    OtaDesiredStateUnusable,
    OtaInstallHalted,
    RobotIdentity,
    configure,
)
from .install_tree import InstallTreeUnusable
from .state_lock import (
    InstallStateBusy,
    InstallStateLockUnavailable,
    install_state_lock,
    install_state_lock_path,
)

__all__ = [
    "ContentHashMismatch",
    "InstallStateBusy",
    "InstallStateLockUnavailable",
    "InstallTreeUnusable",
    "OtaContext",
    "OtaDesiredStateUnusable",
    "OtaInstallHalted",
    "RobotIdentity",
    "configure",
    "install_state_lock",
    "install_state_lock_path",
]
