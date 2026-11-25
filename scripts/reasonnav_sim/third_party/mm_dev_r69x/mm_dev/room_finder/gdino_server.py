#!/usr/bin/env python3
"""Grounding DINO as a tiny local HTTP service.

Grounding DINO needs a transformers release newer than the one the ROS environment carries, so it runs in its own
virtualenv (yolo_ws/.venv_autolabel) and the perception node talks to it over localhost:

    /home/user/yolo_ws/.venv_autolabel/bin/python gdino_server.py [--port 8765] [--model IDEA-Research/grounding-dino-base]

POST /detect  {"image": <base64 jpeg>, "prompt": "navigational signs.", "box_thr": 0.25, "text_thr": 0.2}
           -> {"dets": [{"phrase": str, "score": float, "xyxy": [x1, y1, x2, y2]}], "ms": float}
GET  /health -> {"ok": true}
"""
import argparse
import base64
import io
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import torch
from PIL import Image
from transformers import AutoModelForZeroShotObjectDetection, AutoProcessor

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=8765)
ap.add_argument("--model", default="IDEA-Research/grounding-dino-base")
args = ap.parse_args()

device = "cuda" if torch.cuda.is_available() else "cpu"
proc = AutoProcessor.from_pretrained(args.model)
model = AutoModelForZeroShotObjectDetection.from_pretrained(args.model).to(device).eval()
lock = threading.Lock()


@torch.no_grad()
def detect(img, prompt, box_thr, text_thr):
    inputs = proc(images=img, text=prompt, return_tensors="pt").to(device)
    with torch.autocast("cuda", dtype=torch.float16, enabled=(device == "cuda")):
        out = model(**inputs)
    res = proc.post_process_grounded_object_detection(
        out, inputs.input_ids, threshold=box_thr, text_threshold=text_thr, target_sizes=[img.size[::-1]])[0]
    labels = res.get("text_labels", res.get("labels"))
    return [{"phrase": str(l), "score": float(s), "xyxy": [float(v) for v in b]}
            for b, s, l in zip(res["boxes"], res["scores"], labels)]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send({"ok": True, "model": args.model, "device": device})

    def do_POST(self):
        try:
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            img = Image.open(io.BytesIO(base64.b64decode(req["image"]))).convert("RGB")
            t0 = time.time()
            with lock:
                dets = detect(img, req["prompt"], float(req.get("box_thr", 0.25)), float(req.get("text_thr", 0.2)))
            self._send({"dets": dets, "ms": (time.time() - t0) * 1e3})
        except Exception as e:  # noqa: BLE001
            self._send({"error": repr(e)}, 500)


print(f"[gdino] {args.model} on {device}, http://127.0.0.1:{args.port}", flush=True)
ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
