#!/usr/bin/env python3
"""Report of room-finding trials in the Jinri-gwan world (run_trials.py --world jinri_1f): success table, per-area summary,
plate/sign perception checked against the generated ground truth, and a map of every search.

    jinri_report.py <tag> [<tag> ...] [--out log/reasonnav_sim/full_eval/<first tag>]

Map frame = world - spawn (yaw 0).  A registered sign is matched to the ground-truth sign face within 2.5 m whose entries
share the most room numbers; a cue is "right" when its map bearing is within 45 deg of the ground-truth arrow."""
import argparse
import json
import math
import os
import re
import statistics

import cv2
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.expanduser("~/raisin_ws")
GT = json.load(open(os.path.join(HERE, "..", "gt", "jinri_1f_rooms.json")))
SX, SY = GT["spawn_xy"]
DIRS = {"E": 0.0, "NE": 45.0, "N": 90.0, "NW": 135.0, "W": 180.0, "SW": -135.0, "S": -90.0, "SE": -45.0}


def area(room):
    n = int(re.sub(r"\D", "", room)[:3])
    if 132 <= n <= 146:
        return "west wing (T132-T146)"
    if 101 <= n <= 109:
        return "main corridor east (T101-T109)"
    if 110 <= n <= 121:
        return "east block (T110-T121)"
    return "north corridor (T122-T131)"


def gt_map(xy):
    return xy[0] - SX, xy[1] - SY


def nums(text):
    return [int(m) for m in re.findall(r"(\d{3})", str(text))]


def sign_check(signs):
    """-> list of (registered sign, matched gt face or None, [(cue place, ok bool|None)])"""
    faces = []
    for g in GT["signs"]:
        faces.append(dict(g, mxy=gt_map(g["xy"])))
    out = []
    for s in signs:
        sx, sy = s["xy"] if "xy" in s else (s["x"], s["y"])
        near = [f for f in faces if math.hypot(f["mxy"][0] - sx, f["mxy"][1] - sy) < 2.5]
        cues = s.get("cues", [])
        cue_nums = set(n for c in cues for n in nums(c.get("place", "")))
        best = max(near, key=lambda f: len(cue_nums & set(n for e in f["entries"] for n in nums(e[0]))), default=None)
        res = []
        for c in cues:
            if best is None or c.get("bearing") is None:
                res.append((c.get("place"), None))
                continue
            cn = set(nums(c.get("place", "")))
            ent = max(best["entries"], key=lambda e: len(cn & set(nums(e[0]))))
            if not cn & set(nums(ent[0])):
                res.append((c.get("place"), False))
                continue
            d = abs((math.degrees(c["bearing"]) - DIRS[ent[1]] + 180) % 360 - 180)
            res.append((c.get("place"), d <= 45.0))
        out.append((s, best, res))
    return out


def draw_map(rows, path):
    s = 8.0
    xs = [gt_map(v["xy"])[0] for v in GT["rooms"].values()]
    ys = [gt_map(v["xy"])[1] for v in GT["rooms"].values()]
    x0, x1, y0, y1 = min(xs) - 8, max(xs) + 8, min(ys) - 10, max(ys) + 10
    W, H = int((x1 - x0) * s), int((y1 - y0) * s)
    img = np.full((H, W, 3), 255, np.uint8)
    P = lambda x, y: (int((x - x0) * s), int((y1 - y) * s))  # noqa: E731
    for d in GT["doors"]:
        x, y = gt_map(d["xy"])
        cv2.circle(img, P(x, y), 2, (190, 190, 190), -1)
    for k, v in GT["rooms"].items():
        x, y = gt_map(v["xy"])
        cv2.putText(img, k.replace("~", "-"), (P(x, y)[0] - 14, P(x, y)[1] + (12 if y < 2 else -6)), cv2.FONT_HERSHEY_SIMPLEX, 0.32, (120, 120, 120), 1, cv2.LINE_AA)
    for g in GT["signs"]:
        x, y = gt_map(g["xy"])
        cv2.rectangle(img, (P(x, y)[0] - 3, P(x, y)[1] - 3), (P(x, y)[0] + 3, P(x, y)[1] + 3), (200, 120, 0), -1)
    for r in rows:
        gx, gy = gt_map(GT["rooms"][r["target"]]["xy"])
        col = (40, 160, 40) if r.get("success") else (40, 40, 220)
        cv2.circle(img, P(gx, gy), 7, col, 2)
    cv2.circle(img, P(0, 0), 6, (0, 0, 0), -1)
    cv2.putText(img, "spawn", (P(0, 0)[0] + 8, P(0, 0)[1] + 4), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 0, 0), 1, cv2.LINE_AA)
    cv2.imwrite(path, img)


def goal_trace(logdir):
    pts = []
    try:
        for line in open(os.path.join(logdir, "finder", "finder.log")):
            m = re.search(r"-> .* at \((-?[\d.]+), (-?[\d.]+)\)", line)
            if m:
                pts.append((float(m.group(1)), float(m.group(2))))
    except OSError:
        pass
    return pts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tags", nargs="+")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    rows = []
    for t in a.tags:
        p = os.path.join(WS, "log", "reasonnav_sim", "trials", t + ".jsonl")
        rows += [json.loads(l) for l in open(p) if l.strip()]
    out = a.out or os.path.join(WS, "log", "reasonnav_sim", "full_eval", a.tags[0])
    os.makedirs(out, exist_ok=True)
    lines = ["# Jinri-gwan 1F room finding (%s)" % ", ".join(a.tags), ""]
    ok = [r for r in rows if r.get("success")]
    times = [r["elapsed_s"] for r in ok]
    lines += ["Success: **%d / %d** (%.0f%%)" % (len(ok), len(rows), 100.0 * len(ok) / max(1, len(rows))),
              "Successful searches: median %.0f s, mean %.0f s, max %.0f s; median path %.0f m" % (
                  statistics.median(times) if times else 0, statistics.mean(times) if times else 0, max(times) if times else 0,
                  statistics.median([r["path_len_m"] for r in ok]) if ok else 0), ""]
    lines += ["| room | area | result | time s | path m | label err m | robot err m | plates read | signs read (right/total cues) | note |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    per_area = {}
    sign_tot = [0, 0, 0]
    for r in rows:
        res = None
        try:
            res = json.load(open(os.path.join(r["logdir"], "finder", "result.json")))
        except (OSError, ValueError, KeyError):
            pass
        note = ""
        nplates, ssum = "-", "-"
        if res:
            st = res.get("stats", {})
            nplates = st.get("plate_reads", "-")
            sc = sign_check(res.get("signs", []))
            right = sum(1 for _, _, cs in sc for _, okc in cs if okc)
            judged = sum(1 for _, _, cs in sc for _, okc in cs if okc is not None)
            false_signs = sum(1 for s, best, _ in sc if best is None and s.get("cues"))
            sign_tot[0] += right; sign_tot[1] += judged; sign_tot[2] += false_signs
            ssum = "%d/%d%s" % (right, judged, (", %d false" % false_signs) if false_signs else "")
        if not r.get("success"):
            if r.get("claimed"):
                note = "claimed a wrong place"
            elif r.get("reason"):
                note = r["reason"]
            else:
                note = "gave up / time limit"
        ar = area(r["target"])
        per_area.setdefault(ar, []).append(r)
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["target"], ar.split(" (")[0], "OK" if r.get("success") else "FAIL", r.get("elapsed_s", "-"), r.get("path_len_m", "-"),
            r.get("dist_label_to_gt", "-"), r.get("dist_robot_to_gt", "-"), nplates, ssum, note))
    lines += ["", "| area | success | median time s (successes) |", "|---|---|---|"]
    for ar, rs in sorted(per_area.items()):
        ts = [x["elapsed_s"] for x in rs if x.get("success")]
        lines.append("| %s | %d / %d | %s |" % (ar, sum(1 for x in rs if x.get("success")), len(rs), "%.0f" % statistics.median(ts) if ts else "-"))
    lines += ["", "Sign cues with a direction: %d / %d point the right way (within 45 deg of the printed arrow); %d registered signs with a reading "
              "matched no real sign." % (sign_tot[0], sign_tot[1], sign_tot[2])]
    draw_map(rows, os.path.join(out, "map.png"))
    lines += ["", "![map](map.png)  green = found, red = failed, blue squares = signs, black = spawn (lobby)."]
    open(os.path.join(out, "summary.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print("->", out)


if __name__ == "__main__":
    main()
