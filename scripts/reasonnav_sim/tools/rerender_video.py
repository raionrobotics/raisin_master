#!/usr/bin/env python3
"""Repaint the reasoning panel of already recorded search videos with the VLM crops and answers.

    nice -n 19 python3 rerender_video.py <tag> [room ...]      e.g.  rerender_video.py full1 3001 3002

For every room of log/reasonnav_sim/trials/<tag>.jsonl that has a video, the bottom-right panel (x 1000-1600, y 400-1000) is
redrawn from the logs of that run (perception/events.jsonl, finder.log, perception/crops/): goal and hint from the finder
log, the last plate crops with the VLM answers, the last sign crop with its answer. The camera board and the map of the
original video are kept. The original is moved to videos_orig/.

Limits: videos recorded before 2026-10-01 14:50 have no stored candidate scores (not shown) and no raw sign answers
(the parsed tuples are shown instead); the crop of a read is matched by its file name.
"""
import json, os, re, subprocess, sys

import cv2

sys.path.insert(0, "/home/user/tips_ws/src/ReasonNav/src/mm_dev")
from mm_dev.room_finder.viz import draw_reason_panel  # noqa: E402

WS = os.path.expanduser("~/raisin_ws")
TAIL_S, FPS = 4.0, 5.0
cv2.setNumThreads(1)


def load_run(logdir):
    ev = [json.loads(l) for l in open(f"{logdir}/perception/events.jsonl")]
    crops = set(os.listdir(f"{logdir}/perception/crops"))
    lines, t0 = [], None
    for l in open(f"{logdir}/finder.log"):
        m = re.match(r"\[INFO\] \[([\d.]+)\] \[room_finder\]: \[ *(\d+)s\] (.*)", l.rstrip("\n"))
        if not m:
            continue
        if t0 is None:
            t0 = float(m[1]) - float(m[2])
        goal = re.match(r"-> (.*?) at \(.*?\[hint=(\w+)", m[3])
        lines.append((float(m[1]), "[%4ds] %s" % (int(m[2]), m[3]), (goal[1], goal[2]) if goal else None))
    return ev, crops, lines, t0


def crop_name(e, crops):
    ts = int(e["t"] * 10) % 100000
    for d in (0, -1, 1, -2, 2, -3, 3):
        n = ("%s_d%s_%d_%s.jpg" % (e["source"], e["door"], ts + d, e["number"] or "none")) if e["kind"] == "plate_read" \
            else "sign_s%s_%d.jpg" % (e["sign"], ts + d)
        if n in crops:
            return n
    return None


def rerender(row):
    logdir, src = row["logdir"], row["video"]
    if not src or not os.path.exists(src):
        return "no video"
    ev, crops, lines, t0 = load_run(logdir)
    if any(e["kind"] == "plate_read" and "crop" in e for e in ev):
        return "already has VLM answers"
    cap = cv2.VideoCapture(src)
    n = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    dur = n / FPS
    elapsed = json.load(open(f"{logdir}/finder/result.json"))["elapsed_s"]
    start = t0 + elapsed + TAIL_S - dur           # wall time of video frame 0 (the video ends TAIL_S after DONE)
    plates = [e for e in ev if e["kind"] == "plate_read"]
    signs = [e for e in ev if e["kind"] == "sign_read"]
    cache = {}

    def img(name):
        if name and name not in cache:
            cache[name] = cv2.imread(f"{logdir}/perception/crops/{name}")
        return cache.get(name)
    for e in plates + signs:
        e["_crop"] = crop_name(e, crops)
    tmp = src[:-4] + ".tmp.mp4"
    w = cv2.VideoWriter(tmp, cv2.VideoWriter_fourcc(*"mp4v"), FPS, (1600, 1000))
    last_sig, panel = None, None
    for k in range(n):
        ok, fr = cap.read()
        if not ok:
            break
        T = start + k / FPS
        vis = [l for l in lines if l[0] <= T]
        goal = next((l[2] for l in reversed(vis) if l[2]), None)
        pr = [e for e in plates if e["t"] <= T][-3:]
        sg = [e for e in signs if e["t"] <= T][-1:]
        sig = (len(vis), id(pr[-1]) if pr else 0, id(sg[0]) if sg else 0)
        if sig != last_sig:
            ctx = {"target": row["target"], "item": goal[0] if goal else None, "hint": ("%s (details not recorded)" % goal[1]) if goal else "-",
                   "cands": None, "log": [l[1] for l in vis[-4:]],
                   "reads": [dict(e, crop=img(e["_crop"])) for e in pr],
                   "sign": dict(sg[0], crop=img(sg[0]["_crop"]), raw=None) if sg else None}
            panel, last_sig = draw_reason_panel(ctx), sig
        fr[400:1000, 1000:1600] = panel
        w.write(fr)
    cap.release(); w.release()
    vdir = os.path.dirname(src)
    os.makedirs(vdir + "_orig", exist_ok=True)
    dst = src[:-4] + ".new.mp4"
    r = subprocess.run(["ffmpeg", "-v", "error", "-y", "-threads", "1", "-i", tmp, "-c:v", "libx264", "-crf", "27", "-preset", "veryfast",
                        "-pix_fmt", "yuv420p", "-movflags", "+faststart", dst])
    os.remove(tmp)
    if r.returncode != 0:
        return "ffmpeg failed"
    os.replace(src, vdir + "_orig/" + os.path.basename(src))
    os.replace(dst, src)
    return "ok (%d frames)" % n


if __name__ == "__main__":
    tag = sys.argv[1]
    want = set(sys.argv[2:])
    for l in open(f"{WS}/log/reasonnav_sim/trials/{tag}.jsonl"):
        row = json.loads(l)
        if want and row["target"] not in want:
            continue
        print(row["target"], rerender(row), flush=True)
