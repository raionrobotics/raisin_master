#!/usr/bin/env bash
# Runs on the machine with internet (robot PC).  Builds the offline wheelhouse and copies everything to the AI PC.
#   deploy_to_ai_pc.sh user@host        (ssh asks for the password, or use a key: ssh-copy-id user@host)
set -e
AI=${1:?usage: deploy_to_ai_pc.sh user@host}
HERE=$(cd "$(dirname "$0")" && pwd)
NET=$(dirname "$HERE")
RN=${REASONNAV:-$HOME/tips_ws/src/ReasonNav}
W=${WHEELS:-$HOME/.cache/room_finder_wheels_aarch64}
mkdir -p "$W"
JET=https://pypi.jetson-ai-lab.io/jp6/cu126
if [ ! -f "$W/torch-2.9.1-cp310-cp310-linux_aarch64.whl" ]; then
  curl -fL -o "$W/torch-2.9.1-cp310-cp310-linux_aarch64.whl"            "$JET/+f/02f/de421eabbf626/torch-2.9.1-cp310-cp310-linux_aarch64.whl"
  curl -fL -o "$W/torchvision-0.24.1-cp310-cp310-linux_aarch64.whl"     "$JET/+f/d5b/caaf709f11750/torchvision-0.24.1-cp310-cp310-linux_aarch64.whl"
fi
[ -f "$W"/nvidia_cudss_cu12-0.7.1.4-py3-none-manylinux_2_17_aarch64.whl ] || curl -fL -o "$W"/nvidia_cudss_cu12-0.7.1.4-py3-none-manylinux_2_17_aarch64.whl \
  https://files.pythonhosted.org/packages/94/81/5db4fe70e8ae64399012810652c9952908636363db59b84771bf225532af/nvidia_cudss_cu12-0.7.1.4-py3-none-manylinux_2_17_aarch64.whl
( cd /tmp && pip download -d "$W" --platform manylinux2014_aarch64 --platform manylinux_2_28_aarch64 --platform manylinux_2_17_aarch64 \
    --platform manylinux_2_34_aarch64 --python-version 3.10 --implementation cp --abi cp310 --abi abi3 --abi none --only-binary=:all: \
    transformers==4.57.6 python-dotenv scikit-image scipy pyyaml pytesseract requests pillow opencv-python-headless==4.10.0.84 \
    numpy==1.26.4 pybind11 depthai==3.3.0 matplotlib psutil tqdm polars sympy networkx jinja2 filelock fsspec typing_extensions \
    setuptools huggingface-hub tokenizers safetensors regex packaging )
( cd /tmp && pip download -d "$W" --no-deps ultralytics==8.3.200 ultralytics-thop )
ssh -o PubkeyAuthentication=no "$AI" 'mkdir -p ~/room_finder_deploy/wheels ~/room_finder_deploy/raisin_ws_scripts ~/room_finder_deploy/ReasonNav ~/.cache/huggingface/hub'
tar cf - -C "$W" . | ssh -o PubkeyAuthentication=no "$AI" 'tar xf - -C ~/room_finder_deploy/wheels'
tar czf - -C "$(dirname "$NET")" --exclude=__pycache__ --exclude=raisin_py/build "$(basename "$NET")" | ssh -o PubkeyAuthentication=no "$AI" 'tar xzf - -C ~/room_finder_deploy/raisin_ws_scripts'
tar czf - -C "$RN" --exclude=__pycache__ src/mm_dev room_finder_assets | ssh -o PubkeyAuthentication=no "$AI" 'tar xzf - -C ~/room_finder_deploy/ReasonNav'
# Grounding DINO weights (no internet on the AI PC)
tar czf - -C ~/.cache/huggingface/hub models--IDEA-Research--grounding-dino-base | ssh -o PubkeyAuthentication=no "$AI" 'tar xzf - -C ~/.cache/huggingface/hub'
echo "copied. On the AI PC:  bash ~/room_finder_deploy/raisin_ws_scripts/room_finder_net/ai_pc/setup_ai_pc.sh"
