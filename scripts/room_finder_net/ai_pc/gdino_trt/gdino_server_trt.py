#!/usr/bin/env python3
"""Grounding DINO HTTP service backed by a TensorRT engine (same API as gdino_server.py).

    python gdino_server_trt.py --engine gdino_fp16.engine [--port 8765]

The engine has the prompt and the processed image size baked in (export_gdino_onnx.py writes <onnx>.meta.json next to
it; pass --meta if it is elsewhere).  A request with another prompt or an image that preprocesses to another size is
answered by the PyTorch model, loaded on first use.

POST /detect  {"image": <base64 jpeg>, "prompt": str, "box_thr": 0.25, "text_thr": 0.2}
           -> {"dets": [{"phrase", "score", "xyxy"}], "ms": float, "backend": "trt" | "torch"}
GET  /health -> {"ok": true, ...}
"""
import argparse
import base64
import io
import json
import os
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np
import tensorrt as trt
import torch
from PIL import Image
from transformers import AutoProcessor

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=8765)
ap.add_argument("--engine", required=True)
ap.add_argument("--meta", default="")
a = ap.parse_args()
meta_path = a.meta or next((p for p in (a.engine + ".meta.json", os.path.splitext(a.engine)[0] + ".onnx.meta.json",
                                        os.path.join(os.path.dirname(a.engine) or ".", "gdino.onnx.meta.json"))
                            if os.path.exists(p)), None)
if not meta_path:
    raise SystemExit("no meta.json for %s (use --meta)" % a.engine)
meta = json.load(open(meta_path))
proc = AutoProcessor.from_pretrained(meta["model"])
input_ids = torch.tensor(meta["input_ids"])
lock = threading.Lock()


class Engine:
    def __init__(self, path):
        log = trt.Logger(trt.Logger.WARNING)
        trt.init_libnvinfer_plugins(log, "")
        self.eng = trt.Runtime(log).deserialize_cuda_engine(open(path, "rb").read())
        self.ctx = self.eng.create_execution_context()
        self.bufs = {}
        for i in range(self.eng.num_io_tensors):
            n = self.eng.get_tensor_name(i)
            dt = {trt.float32: torch.float32, trt.float16: torch.float16}[self.eng.get_tensor_dtype(n)]
            self.bufs[n] = torch.empty(tuple(self.eng.get_tensor_shape(n)), dtype=dt, device="cuda")
            self.ctx.set_tensor_address(n, self.bufs[n].data_ptr())
        self.stream = torch.cuda.Stream()

    def __call__(self, pixel_values):
        self.bufs["pixel_values"].copy_(pixel_values)
        with torch.cuda.stream(self.stream):
            self.ctx.execute_async_v3(self.stream.cuda_stream)
        self.stream.synchronize()
        return self.bufs["logits"].float().cpu(), self.bufs["pred_boxes"].float().cpu()


engine = Engine(a.engine)
torch_model = None


def post(logits, boxes, ids, img, box_thr, text_thr):
    out = types.SimpleNamespace(logits=logits, pred_boxes=boxes)
    res = proc.post_process_grounded_object_detection(out, ids, threshold=box_thr, text_threshold=text_thr,
                                                      target_sizes=[img.size[::-1]])[0]
    labels = res.get("text_labels", res.get("labels"))
    return [{"phrase": str(l), "score": float(s), "xyxy": [float(v) for v in b]}
            for b, s, l in zip(res["boxes"], res["scores"], labels)]


@torch.no_grad()
def detect(img, prompt, box_thr, text_thr):
    global torch_model
    if prompt == meta["prompt"]:
        pv = proc.image_processor(images=img, return_tensors="pt")["pixel_values"]
        if list(pv.shape) == meta["pixel_values_shape"]:
            lg, bx = engine(pv.cuda())
            return post(lg, bx, input_ids, img, box_thr, text_thr), "trt"
    if torch_model is None:
        from transformers import AutoModelForZeroShotObjectDetection
        torch_model = AutoModelForZeroShotObjectDetection.from_pretrained(meta["model"]).cuda().eval()
    inputs = proc(images=img, text=prompt, return_tensors="pt").to("cuda")
    with torch.autocast("cuda", dtype=torch.float16):
        o = torch_model(**inputs)
    return post(o.logits.float().cpu(), o.pred_boxes.float().cpu(), inputs.input_ids.cpu(), img, box_thr, text_thr), "torch"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send({"ok": True, "model": meta["model"], "device": "cuda", "backend": "trt", "engine": a.engine,
                    "prompt": meta["prompt"], "size": meta["image_size"]})

    def do_POST(self):
        try:
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            img = Image.open(io.BytesIO(base64.b64decode(req["image"]))).convert("RGB")
            t0 = time.time()
            with lock:
                dets, backend = detect(img, req["prompt"], float(req.get("box_thr", 0.25)), float(req.get("text_thr", 0.2)))
            self._send({"dets": dets, "ms": (time.time() - t0) * 1e3, "backend": backend})
        except Exception as e:  # noqa: BLE001
            self._send({"error": repr(e)}, 500)


print(f"[gdino-trt] {meta['model']} engine {a.engine}, prompt {meta['prompt']!r}, http://127.0.0.1:{a.port}", flush=True)
ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()
