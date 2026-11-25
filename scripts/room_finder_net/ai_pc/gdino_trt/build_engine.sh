#!/usr/bin/env bash
# Grounding DINO -> ONNX (fixed prompt, 1280x800) -> TensorRT fp16 engine, then a detection check against PyTorch.
#   build_engine.sh [OUT_DIR=~/gdino_trt] [frames for the check: *.jpg ...]
# Run with the venv that has torch + transformers + onnx; trtexec from JetPack (/usr/src/tensorrt/bin) or PATH.
# onnx:  pip install onnx && pip install "numpy==1.26.4"   (onnx pulls numpy 2.x; the Jetson torch wheel wants 1.26.
#        onnx 1.23 + ml_dtypes 0.6 + numpy 1.26 imports fine; pip check still warns about ml_dtypes)
# Orin AGX 64 GB, TensorRT 10.3: the fp16 build takes ~18 min; GDINO base 1280x800 then runs 379 ms (PyTorch fp16 640 ms).
# Serve it:  gdino_server_trt.py --engine $OUT/gdino_fp16.engine   (same API/port as run_gdino.sh)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HOME/gdino_trt}; shift || true
PY=${PY:-$HOME/room_finder_venv/bin/python}
TRTEXEC=${TRTEXEC:-$(command -v trtexec || echo /usr/src/tensorrt/bin/trtexec)}
mkdir -p "$OUT"
[ -f "$OUT/gdino.onnx" ] || "$PY" "$HERE/export_gdino_onnx.py" --out "$OUT/gdino.onnx"
[ -f "$OUT/gdino_fp16.engine" ] || "$TRTEXEC" --onnx="$OUT/gdino.onnx" --saveEngine="$OUT/gdino_fp16.engine" --fp16 | tee "$OUT/trtexec_fp16.log" | grep -E "Throughput|GPU Compute Time|Error"
cp "$OUT/gdino.onnx.meta.json" "$OUT/gdino_fp16.engine.meta.json"
[ $# -gt 0 ] && "$PY" "$HERE/parity.py" --engine "$OUT/gdino_fp16.engine" --meta "$OUT/gdino.onnx.meta.json" --trtexec "$TRTEXEC" "$@"
echo "engine: $OUT/gdino_fp16.engine   serve:  $PY $HERE/gdino_server_trt.py --engine $OUT/gdino_fp16.engine"
