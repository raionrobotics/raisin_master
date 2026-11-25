#!/usr/bin/env python3
"""Summarise one room-finder run's perception log (events.jsonl): door detections, Grounding DINO boxes, sign OCR/reads,
plate reads and pose lag -- to see why doors are over-detected or signs dropped on the real robot.

    diag_run.py [RUN_DIR]      (default: the newest ~/raisin_ws/log/room_finder_net/*/)"""
import collections
import glob
import json
import os
import shutil
import sys

import numpy as np

run = sys.argv[1] if len(sys.argv) > 1 else max(glob.glob(os.path.expanduser("~/raisin_ws/log/room_finder_net/*/")), key=os.path.getmtime)
ev_path = os.path.join(run, "perception", "events.jsonl")
ev = [json.loads(l) for l in open(ev_path) if l.strip()]
print("run", run, "|", len(ev), "events")
kinds = collections.Counter(e["kind"] for e in ev)
print("kinds", dict(kinds))


def q(v, name):
    v = np.asarray([x for x in v if x is not None], float)
    if not len(v):
        return "%s: none" % name
    p = np.percentile(v, [10, 50, 90])
    return "%s: n %d  p10 %.2f  median %.2f  p90 %.2f  max %.2f" % (name, len(v), p[0], p[1], p[2], v.max())


dd = [e for e in ev if e["kind"] == "door_det"]
if dd:
    print("\n== door_det (YOLO boxes with depth, before the size/flush filters; only z < 9 m are logged)")
    print(q([e["conf"] for e in dd], "conf"))
    print(q([e["z"] for e in dd], "z m"))
    print(q([e["w"] for e in dd], "width m"))
    print(q([e["h"] for e in dd], "height m"))
    print(q([e.get("prot") for e in dd], "protrusion m"))
    ok = [e for e in dd if 0.6 <= e["w"] <= 2.4 and (e["clipped"] or 1.4 <= e["h"] <= 2.9) and (e.get("prot") is None or e["prot"] <= 0.30)]
    print("pass size+flush filters: %d / %d   (clipped boxes: %d)" % (len(ok), len(dd), sum(e["clipped"] for e in dd)))
    print("passing, by conf: <0.3 %d, 0.3-0.5 %d, >=0.5 %d" % (sum(e["conf"] < 0.3 for e in ok), sum(0.3 <= e["conf"] < 0.5 for e in ok),
                                                         sum(e["conf"] >= 0.5 for e in ok)))
    print("passing, by z: <3 m %d, 3-6 m %d, >=6 m %d" % (sum(e["z"] < 3 for e in ok), sum(3 <= e["z"] < 6 for e in ok), sum(e["z"] >= 6 for e in ok)))
    print("per camera", dict(collections.Counter(e["cam"] for e in dd)))

gd = [e for e in ev if e["kind"] == "gdino"]
print("\n== gdino boxes with depth: %d" % len(gd))
if gd:
    print("phrases", collections.Counter(e["phrase"] for e in gd).most_common(8))
    print(q([e["score"] for e in gd], "score"))
    sg = [e for e in gd if "sign" in e["phrase"]]
    print(q([e["w_m"] for e in sg], "sign w m"), "|", q([e["h_m"] for e in sg], "sign h m"), "|", q([e["z"] for e in sg], "sign z m"))
    passing = [e for e in sg if 0.45 <= e["w_m"] <= 2.4 and 0.35 <= e["h_m"] <= 2.4 and 0.55 <= e["h_m"] / max(e["w_m"], 1e-3) <= 1.8]
    print("sign boxes passing the 'navigational sign panel' size rule (w 0.45-2.4, h 0.35-2.4, h/w 0.55-1.8): %d / %d" % (len(passing), len(sg)))
    for e in sg[:12]:
        print("   ", e["cam"], e["phrase"], e["score"], "w %.2f h %.2f z %.2f" % (e["w_m"], e["h_m"], e["z"]))

for k in ("sign_ocr", "sign_read", "plate_read", "pose_lag"):
    xs = [e for e in ev if e["kind"] == k]
    print("\n== %s: %d" % (k, len(xs)))
    for e in xs[:10]:
        r = {kk: vv for kk, vv in e.items() if kk not in ("t", "kind", "raw")}
        if "cues" in r:
            r["cues"] = [(c.get("place"), c.get("direction")) for c in r["cues"]]
        print("   ", str(r)[:300])
    if k == "pose_lag" and xs:
        for key in xs[0]:
            if key not in ("t", "kind", "cam") and isinstance(xs[0][key], (int, float)):
                print("   ", q([e.get(key) for e in xs], key))

crops = glob.glob(os.path.join(run, "perception", "crops", "*.jpg"))
print("\ncrops:", len(crops), collections.Counter(os.path.basename(c).split("_")[0] for c in crops))
print("tesseract binary:", shutil.which("tesseract"))
if shutil.which("tesseract"):
    os.system("tesseract --list-langs 2>&1 | tail -n +2 | tr '\\n' ' '; echo")
