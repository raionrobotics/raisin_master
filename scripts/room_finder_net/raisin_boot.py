"""Call preload() before `import raisin_py`.

raisin_network loads its encryption plug-in (libraisin_empty_encryption.so) with dlopen(path found under the build / install tree of the
*executable*).  A python process lives in /usr/bin, so nothing is found and the lookup falls through to dlsym(main program, "create").
Loading the plug-in RTLD_GLOBAL first makes that lookup succeed whatever the layout of the raisin install is."""
import ctypes
import glob
import os

NAME = "libraisin_empty_encryption.so"


def preload():
    # $RAISIN_WS, else the workspace holding this script (<ws>/scripts/room_finder_net), so a renamed workspace keeps its own install
    here = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    cands = []
    for ws in dict.fromkeys(w for w in (os.environ.get("RAISIN_WS"), here, os.path.expanduser("~/raisin_ws")) if w):
        cands += [os.path.join(ws, "install", "lib", NAME)]
        cands += glob.glob(os.path.join(ws, "cmake-build-release", "src", "raisin", "raisin_encryption", "*", NAME))
        cands += glob.glob(os.path.join(ws, "**", NAME), recursive=False)
    cands += [os.path.expanduser("~/raisin_master/install/lib/" + NAME)]
    for c in cands:
        if os.path.exists(c):
            ctypes.CDLL(c, mode=ctypes.RTLD_GLOBAL)
            return c
    return None
