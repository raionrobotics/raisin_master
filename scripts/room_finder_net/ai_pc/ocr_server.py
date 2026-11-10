#!/usr/bin/env python3
"""Scene-text OCR HTTP service for room_perception (RapidOCR = PP-OCRv4 det + rec, on the GPU through onnxruntime-gpu).

    ~/ocr_venv/bin/python ai_pc/ocr_server.py [--port 8767] [--cpu]

Runs in its own venv (rapidocr_onnxruntime + the Jetson onnxruntime-gpu wheel), apart from the perception venv.
POST /ocr   body: raw BGR uint8 image, headers X-Width / X-Height  -> {"items": [{"text", "conf", "box": [x0, y0, x1, y1]}], "ms"}
GET  /health
On the 11-10 hand-driven recording (3 x 12 MP cameras) it read all 16 plates T101..T117 the robot passed (conf >= 0.98), while
GDINO had no box on several of them (a bigger nameplate next to the plate won). 12 MP frame: ~350 ms on the Orin GPU."""
import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np
from rapidocr_onnxruntime import RapidOCR

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=8767)
ap.add_argument("--cpu", action="store_true", help="onnxruntime on the CPU (~1.2 s per 12 MP frame)")
ap.add_argument("--min-conf", type=float, default=0.5, help="texts below this recognition confidence are not returned")
a = ap.parse_args()
gpu = not a.cpu
ocr = RapidOCR(det_use_cuda=gpu, rec_use_cuda=gpu, cls_use_cuda=gpu, use_cls=False)
lock = threading.Lock()


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
        self._send({"ok": True, "gpu": gpu})

    def do_POST(self):
        try:
            w, h = int(self.headers["X-Width"]), int(self.headers["X-Height"])
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            img = np.frombuffer(raw, np.uint8).reshape(h, w, 3)
            t0 = time.time()
            with lock:
                res, _ = ocr(img, use_cls=False)
            items = []
            for box, txt, conf in res or []:
                if float(conf) >= a.min_conf:
                    xs, ys = [p[0] for p in box], [p[1] for p in box]
                    items.append({"text": txt, "conf": round(float(conf), 3), "box": [float(min(xs)), float(min(ys)), float(max(xs)), float(max(ys))]})
            self._send({"items": items, "ms": round((time.time() - t0) * 1e3, 1)})
        except Exception as e:  # noqa: BLE001
            self._send({"error": repr(e)}, 500)


ocr(np.zeros((64, 64, 3), np.uint8))   # load the models (CUDA init) before serving
print("[ocr] RapidOCR on %s, http://127.0.0.1:%d" % ("GPU" if gpu else "CPU", a.port), flush=True)
ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()
