#!/usr/bin/env python3
"""Detections from PyTorch (the server's autocast fp16 path) vs a TensorRT engine run through trtexec, on real frames.

    python parity.py --engine gdino_fp16.engine --meta gdino.onnx.meta.json img1.jpg img2.jpg ...
Frames are resized to the engine's image size first (what the perception node sends)."""
import argparse
import json
import os
import subprocess
import tempfile
import time
import types

import numpy as np
import torch
from PIL import Image
from transformers import AutoModelForZeroShotObjectDetection, AutoProcessor

ap = argparse.ArgumentParser()
ap.add_argument("--engine", required=True)
ap.add_argument("--meta", required=True)
ap.add_argument("--trtexec", default="trtexec")
ap.add_argument("--box-thr", type=float, default=0.3)
ap.add_argument("--text-thr", type=float, default=0.25)
ap.add_argument("images", nargs="+")
a = ap.parse_args()
meta = json.load(open(a.meta))
proc = AutoProcessor.from_pretrained(meta["model"])
model = AutoModelForZeroShotObjectDetection.from_pretrained(meta["model"]).cuda().eval()
ids = torch.tensor(meta["input_ids"])
W, H = meta["image_size"]


def post(lg, bx, img):
    res = proc.post_process_grounded_object_detection(types.SimpleNamespace(logits=lg, pred_boxes=bx), ids, threshold=a.box_thr,
                                                      text_threshold=a.text_thr, target_sizes=[img.size[::-1]])[0]
    labels = res.get("text_labels", res.get("labels"))
    return sorted([(str(l), round(float(s), 3), [round(float(v)) for v in b]) for b, s, l in zip(res["boxes"], res["scores"], labels)],
                  key=lambda d: -d[1])


def iou(p, q):
    x1, y1, x2, y2 = max(p[0], q[0]), max(p[1], q[1]), min(p[2], q[2]), min(p[3], q[3])
    i = max(0, x2 - x1) * max(0, y2 - y1)
    return i / ((p[2] - p[0]) * (p[3] - p[1]) + (q[2] - q[0]) * (q[3] - q[1]) - i + 1e-9)


tmp = tempfile.mkdtemp()
times = []
for path in a.images:
    img = Image.open(path).convert("RGB").resize((W, H))
    inputs = proc(images=img, text=meta["prompt"], return_tensors="pt").to("cuda")
    with torch.no_grad(), torch.autocast("cuda", dtype=torch.float16):
        for _ in range(2):
            o = model(**inputs)
        torch.cuda.synchronize(); t = time.time()
        o = model(**inputs)
        torch.cuda.synchronize(); times.append(time.time() - t)
    ref = post(o.logits.float().cpu(), o.pred_boxes.float().cpu(), img)
    pv = os.path.join(tmp, "pv.bin"); out = os.path.join(tmp, "out.json")
    inputs["pixel_values"].float().cpu().numpy().tofile(pv)
    subprocess.run([a.trtexec, "--loadEngine=" + a.engine, "--loadInputs=pixel_values:" + pv, "--exportOutput=" + out,
                    "--iterations=1", "--warmUp=0", "--duration=0"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    d = {e["name"]: np.array(e["values"], np.float32).reshape([int(x) for x in e["dimensions"].split("x")])
         for e in json.loads(open(out).read().replace("-inf", "-1e30").replace("nan", "0"))}
    trt_d = post(torch.from_numpy(d["logits"]), torch.from_numpy(d["pred_boxes"]), img)
    matched = sum(1 for r in ref if any(t[0] == r[0] and iou(t[2], r[2]) > 0.7 and abs(t[1] - r[1]) < 0.05 for t in trt_d))
    print("%s: torch %d dets, trt %d dets, matched %d" % (os.path.basename(path), len(ref), len(trt_d), matched))
    for r in ref[:4]:
        print("   torch", r)
    for t in trt_d[:4]:
        print("   trt  ", t)
print("torch fp16-autocast forward %.0f ms" % (1e3 * float(np.median(times))))
