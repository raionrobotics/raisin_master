# deps/

Every raisin package declares the apt packages it needs, and the udev rules its devices need, in
its own `deps/`. This file describes those files once for all packages, raisin_master included.
Read it before adding, removing or moving a package in them.

```mermaid
flowchart LR
    deps["deps/<br/>(in each package)"] --> shared["scripts/install_package_deps.sh<br/>(raisin_master, one copy)"]
    shared --> script["workspace root install_dependencies.sh<br/>(host development PC)"]
    deps --> publish["raisin publish<br/>(deps/ and the installer copied into the archive)"]
    shared --> publish
```

The workspace root `install_dependencies.sh` (raisin_master) installs every package's `deps/` with
`scripts/install_package_deps.sh`. A package does not keep its own `install_dependencies.sh`:
`raisin publish` copies the shared one into the package's install tree under that name, where
robots run it.

## Files

| File | Contents |
|---|---|
| `apt.txt` | Libraries the package uses, and what it needs to **run**, every Ubuntu version |
| `apt.ubuntu-<version>.txt` | Same, for that Ubuntu version only |
| `apt.build.txt` | What **building, testing and analysing** it adds on top of `apt.txt` |
| `apt.build.ubuntu-<version>.txt` | Same, for that Ubuntu version only |
| `udev/<name>.rules` | udev rules that let a user without root open the package's devices |

Every file is optional: create one only when it has something to list. A package that needs
nothing from apt has no `apt*.txt`, and installing prints that nothing is declared and moves on.

## Format

- apt package names only, separated by spaces or newlines, one per line by convention.
  pip packages (raisin_master `requirements.txt`) and other host setup such as user groups or
  symlinks do not go here.
- `#` starts a comment. Write why the package is needed: which subpackage uses it, what it links.

```
# raisin_svt_av1 builds its assembly with nasm
nasm
```

### udev rules

- One file per device vendor or model, a standard udev rules file. Its name is the name it gets in
  `/etc/udev/rules.d/`, so start it with a number when the order matters (`99-flir-boson.rules`).
- Installing copies a rule only when it is new or differs, and then reloads udev and re-applies
  the rules to USB devices. Where udev does not run (a container), the rules are skipped with a
  notice: they are host settings.
- A rule is only needed for running without root. The robot node runs as root.

## Which file

Decide in this order:

1. **The code links or includes it (a library)** → `apt.txt`, as the `-dev` package.
   Runtime library package names change between Ubuntu versions; the `-dev` name does not.
   Examples: `libssl-dev`, `libusb-1.0-0-dev`.
2. **Only building, testing, analysing or documenting uses it (a tool)** → `apt.build.txt`.
   Examples: `build-essential`, `nasm`, `pkg-config`, `cmake`, `clang-tidy`, `doxygen`, `gdb`.
3. Common cases settled in advance:
   - `libgtest-dev` → `apt.build.txt` (tests only).
   - `protobuf-compiler` → `apt.build.txt`; `libprotobuf-dev` → `apt.txt`.
4. A name already in `apt.txt` is not repeated in `apt.build.txt`.
5. Use an `ubuntu-<version>` file only when the package name differs by Ubuntu version
   (22.04 `libgeographic-dev`, 24.04 `libgeographiclib-dev`).
6. The package that uses a dependency directly declares it, even when another package already
   installs the same name; otherwise this package breaks when the other one drops it.

## Checking a change

1. **The name exists on every supported Ubuntu version.** Installing fails, and installs nothing,
   when any declared name has no installable candidate. On each version, `apt-cache policy <name>`
   must show a `Candidate:` other than `(none)`.
2. **Installing still succeeds:** run the workspace root `install_dependencies.sh`.
