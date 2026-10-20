#!/usr/bin/env bash
# Runs ON the AI PC (Jetson Orin, aarch64, no internet).  Installs from an offline wheelhouse, builds raisin_py.
#   setup_ai_pc.sh [DEPLOY_DIR=~/room_finder_deploy] [RAISIN_WS=~/raisin_master]
# DEPLOY_DIR holds: wheels/ (torch, torchvision from the Jetson index + aarch64 wheels), raisin_ws_scripts/room_finder_net,
#                   ReasonNav/{src/mm_dev,room_finder_assets}
set -e
D=${1:-$HOME/room_finder_deploy}
RWS=${2:-$HOME/raisin_master}
V=$HOME/room_finder_venv
# python3-venv (ensurepip) is not installed on the AI PC: make the venv without pip and bootstrap pip from the wheelhouse
rm -rf "$V"
python3 -m venv --without-pip "$V"
python3 "$(ls "$D"/wheels/pip-*.whl | head -1)/pip" --python "$V/bin/python" install --no-index --find-links "$D/wheels" pip setuptools wheel
# torch/torchvision are the Jetson builds (link against the system CUDA 12.6 / cuDNN 9); everything else is a plain aarch64 wheel
"$V/bin/pip" install --no-index --find-links "$D/wheels" \
    "$D"/wheels/torch-2.9.1-cp310-cp310-linux_aarch64.whl "$D"/wheels/torchvision-0.24.1-cp310-cp310-linux_aarch64.whl
# the Jetson torch wheel needs libcudss.so.0 (not part of JetPack): plain aarch64 wheel from PyPI, linked next to torch's own libs
"$V/bin/pip" install --no-index --no-deps "$D"/wheels/nvidia_cudss_cu12-*aarch64.whl
SP=$("$V/bin/python" -c 'import site;print(site.getsitepackages()[0])')
for f in "$SP"/nvidia/cu12/lib/libcudss*.so*; do ln -sf "$f" "$SP/torch/lib/$(basename "$f")"; done
"$V/bin/pip" install --no-index --find-links "$D/wheels" \
    numpy==1.26.4 opencv-python-headless==4.10.0.84 scipy scikit-image pyyaml pytesseract requests pillow python-dotenv \
    transformers==4.57.6 matplotlib psutil tqdm polars pybind11 depthai==3.3.0
"$V/bin/pip" install --no-index --no-deps --find-links "$D/wheels" ultralytics ultralytics-thop
"$V/bin/python" - <<'EOF'
import torch, torchvision, cv2, numpy, depthai, ultralytics, transformers
print("torch", torch.__version__, "cuda", torch.cuda.is_available(), "| torchvision", torchvision.__version__, "| cv2", cv2.__version__,
      "| numpy", numpy.__version__, "| depthai", depthai.__version__, "| ultralytics", ultralytics.__version__, "| transformers", transformers.__version__)
EOF
# raisin_py: the pybind11 binding of libraisin_network, built against this PC's raisin install tree
R="$D/raisin_ws_scripts/room_finder_net/raisin_py"
"$V/bin/pip" show pybind11 >/dev/null
cmake -S "$R" -B "$R/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$RWS/install" \
      -Dpybind11_DIR="$("$V/bin/python" -c 'import pybind11;print(pybind11.get_cmake_dir())')" -DPython3_EXECUTABLE="$V/bin/python"
cmake --build "$R/build" -j"$(nproc)"
echo "ok: venv $V, binding $(ls "$R"/build/raisin_py*.so)"
