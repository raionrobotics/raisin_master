"""requirements.txt is the lock generated from requirements.in by the commit hook.

A commit made without the hook (git commit --no-verify, a PC where ./raisin --install
did not install it, such as one that already had its own pre-commit hook, the GitHub web
editor) can change requirements.in alone. These tests catch that without the network: every
version requirements.in pins must be the one requirements.txt installs.
"""

from pathlib import Path
import re

REPO = Path(__file__).resolve().parent
FIX = "Regenerate it with: pre-commit run pip-compile --config .githooks/pre-commit-config.yaml --files requirements.in"


def pins(path: Path) -> dict:
    """name -> version of every `name==version` line, names normalised as pip compares them."""
    found = {}
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if "==" in line:
            name, version = line.split("==", 1)
            found[re.sub(r"[-_.]+", "-", name.strip()).lower()] = version.strip()
    return found


def test_every_package_requirements_in_pins_is_locked_at_that_version():
    wanted = pins(REPO / "requirements.in")
    locked = pins(REPO / "requirements.txt")

    differ = {name: (version, locked.get(name)) for name, version in wanted.items() if locked.get(name) != version}

    assert not differ, f"requirements.txt does not match requirements.in (name: (in, txt)): {differ}. {FIX}"


def test_requirements_in_pins_every_package_it_lists():
    # The lock keeps what requirements.in pins; an unpinned name would float to whatever the
    # last regeneration resolved.
    names = [
        line.split("#", 1)[0].strip()
        for line in (REPO / "requirements.in").read_text().splitlines()
    ]

    unpinned = [name for name in names if name and "==" not in name]

    assert not unpinned, f"requirements.in lists packages without ==version: {unpinned}"
