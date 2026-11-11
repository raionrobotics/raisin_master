#!/usr/bin/env python3
"""Render a room-finder run from its logs into a video (or one PNG): the :8081 map view from the gateway's --log-dir log and the
:8082 camera view from ai_main's --log-debug-hz frames, lined up on the robot PC clock.

  render_video.py --gw <gateway log dir> --run <ai_main run dir> [--out <run dir>/video.mp4] [--speed 8] [--fps 15]
  render_video.py --gw <gateway log dir> --still end --out map.png         # one frame: 'end' or seconds from the start

--layout both (map + panel above, cameras below; needs --run) | map | cams. --view fit (whole explored area, fixed) | follow
(centred on the robot, --scale px per m). --from / --to: seconds from the start. The video starts at the first camera frame
(or the finder's first state) and ends 8 s after the finder is done. H.264 through ffmpeg when it is installed (the AI PC has
it), MPEG-4 part 2 through OpenCV otherwise. Needs numpy, opencv and pillow (~/room_finder_venv on the AI PC).
"""
import argparse
import bisect
import csv
import glob
import json
import math
import os
import re
import shutil
import subprocess
import sys

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

# the light theme of robot_pc/viewer.html
C = {"free": (255, 255, 255), "occ": (29, 35, 48), "unk": (201, 206, 214), "robot": (21, 112, 239), "trail": (83, 177, 253),
     "goal": (217, 45, 32), "door": (181, 71, 8), "label": (7, 148, 85), "sign": (220, 104, 3), "dead": (152, 162, 179),
     "text": (29, 35, 48), "muted": (102, 112, 133), "panel": (255, 255, 255), "line": (208, 213, 221), "bg": (244, 245, 247)}
C["infl"] = tuple(int(round(f * 0.6 + o * 0.4)) for f, o in zip(C["free"], C["occ"]))
_FONTS = {}


def font(size, bold=False):
    key = (size, bold)
    if key not in _FONTS:
        cands = ["/usr/share/fonts/opentype/noto/NotoSansCJK-%s.ttc" % ("Bold" if bold else "Regular"),
                 "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
        f = None
        for p in cands:
            if os.path.exists(p):
                f = ImageFont.truetype(p, size, index=1 if p.endswith(".ttc") else 0)   # .ttc face 1 = KR
                break
        _FONTS[key] = f or ImageFont.load_default()
    return _FONTS[key]


def text(d, s, x, y, col, size=13, bold=False, outline=True):
    d.text((x, y), s, fill=col, font=font(size, bold), stroke_width=2 if outline else 0, stroke_fill=C["panel"])


def wrap(s, f, width):
    out, cur = [], ""
    for ch in s:
        if ch == "\n" or f.getlength(cur + ch) > width:
            out.append(cur)
            cur = "" if ch in "\n " else ch
        else:
            cur += ch
    return out + ([cur] if cur else [])


class Maps:
    """map/<robot PC time ms>.npz snapshots: data (row 0 = lowest y; 0 free, 99 inflated, 100 occupied, -1 unknown), x0, y0, res"""

    def __init__(self, gw):
        self.f = sorted(glob.glob(os.path.join(gw, "map", "*.npz")))
        self.t = [int(os.path.basename(f)[:-4]) / 1000.0 for f in self.f]
        self.k, self.m = None, None

    def at(self, t):
        i = max(0, bisect.bisect_right(self.t, t) - 1)
        if not self.f:
            return None, -1
        if i != self.k:
            z = np.load(self.f[i])
            self.m, self.k = (z["data"], float(z["x0"]), float(z["y0"]), float(z["res"])), i
        return self.m, i


class View:
    def __init__(self, W, H, cx, cy, s):
        self.W, self.H, self.cx, self.cy, self.s = W, H, cx, cy, s

    def px(self, x, y):
        return self.W / 2 + (x - self.cx) * self.s, self.H / 2 - (y - self.cy) * self.s

    def raster(self, m):
        img = np.empty((self.H, self.W, 3), np.uint8)
        img[:] = C["unk"]
        if m is None:
            return img
        data, x0, y0, res = m
        h, w = data.shape
        c = np.floor((self.cx + (np.arange(self.W) + 0.5 - self.W / 2) / self.s - x0) / res).astype(int)
        r = np.floor((self.cy - (np.arange(self.H) + 0.5 - self.H / 2) / self.s - y0) / res).astype(int)
        vals = data[np.clip(r, 0, h - 1)][:, np.clip(c, 0, w - 1)].astype(np.int16)
        vals[~(((r >= 0) & (r < h))[:, None] & ((c >= 0) & (c < w))[None, :])] = -1
        img[vals == 0] = C["free"]
        img[vals == 99] = C["infl"]
        img[vals == 100] = C["occ"]
        return img


def fit_view(W, H, m, pts):
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    if m is not None:
        data, x0, y0, res = m
        rr, cc = np.nonzero(data != -1)
        if rr.size:
            xs += [x0 + cc.min() * res, x0 + (cc.max() + 1) * res]
            ys += [y0 + rr.min() * res, y0 + (rr.max() + 1) * res]
    if not xs:
        return View(W, H, 0.0, 0.0, 20.0)
    x0, x1, y0, y1 = min(xs) - 2, max(xs) + 2, min(ys) - 2, max(ys) + 2
    return View(W, H, (x0 + x1) / 2, (y0 + y1) / 2, min(W / (x1 - x0), H / (y1 - y0)) * 0.96)


def draw_map(img, v, st, trail):
    im = Image.fromarray(img)
    d = ImageDraw.Draw(im)
    if len(trail) > 1:
        d.line([v.px(x, y) for x, y in trail], fill=C["trail"], width=3, joint="curve")
    viz = st.get("_viz") or {}
    reg, fin = viz.get("registry") or {}, viz.get("finder") or {}
    target = str(fin["target"]) if fin.get("target") is not None else None
    tm = re.match(r"^([A-Z]*)(\d+)", (target or "").upper())
    tpre, tnum = (tm.group(1), int(tm.group(2))) if tm else ("", None)
    k = max(1.0, v.s / 30.0) ** 0.5            # glyphs grow a little when zoomed in
    for s in reg.get("signs") or []:            # signs + their cues (a bent arrow: 1.2 m along the first leg, then the second)
        col = C["dead"] if s.get("dead") else C["sign"]
        X, Y = v.px(s["x"], s["y"])
        for c in s.get("cues") or []:
            b = c.get("bearing")
            if b is None:
                continue
            hit = tnum is not None and c.get("lo") is not None and c.get("hi") is not None and (c.get("pre") or "") == tpre \
                and int(c["lo"]) <= tnum <= int(c["hi"])
            b2 = c.get("bearing2")
            L1 = max(1.2 * v.s, 10) if b2 is not None else 0.0
            L = max((3.5 if hit else 1.6) * v.s, 26 if hit else 16)
            mx, my = X + L1 * math.cos(b), Y - L1 * math.sin(b)
            bb = b2 if b2 is not None else b
            ex, ey = mx + L * math.cos(bb), my - L * math.sin(bb)
            cc = C["goal"] if hit else col
            d.line([(X, Y)] + ([(mx, my)] if b2 is not None else []) + [(ex, ey)], fill=cc, width=4 if hit else 2)
            a, ah = math.atan2(ey - my, ex - mx), 9 * k
            d.polygon([(ex, ey), (ex - ah * math.cos(a - 0.4), ey - ah * math.sin(a - 0.4)),
                       (ex - ah * math.cos(a + 0.4), ey - ah * math.sin(a + 0.4))], fill=cc)
            if c.get("place") and (hit or v.s >= 12):
                text(d, str(c["place"]), ex + 4, ey - 16, cc, 12, hit)
        r = 6 * k
        d.polygon([(X, Y - r), (X + r, Y), (X, Y + r), (X - r, Y)], fill=col)
    for dr in reg.get("doors") or []:
        X, Y = v.px(dr["x"], dr["y"])
        w = max(6.0, (dr.get("width") or 0.9) * v.s) / 2
        n = dr.get("nrm")
        ux, uy = (-n[1], -n[0]) if n else (1.0, 0.0)          # along the wall, in image coordinates (y down)
        nn = math.hypot(ux, uy) or 1.0
        d.line([(X - w * ux / nn, Y - w * uy / nn), (X + w * ux / nn, Y + w * uy / nn)], fill=C["door"], width=max(3, int(4 * k)))
        if dr.get("label") and v.s >= 8:
            hit = str(dr["label"]) == target
            text(d, str(dr["label"]), X + 6, Y - 18, C["goal"] if hit else C["door"], 12, hit)
    for lb in reg.get("labels") or []:
        X, Y = v.px(lb["x"], lb["y"])
        hit = lb.get("number") is not None and str(lb["number"]) == target
        r = (7 if hit else 4) * k
        d.ellipse([X - r, Y - r, X + r, Y + r], fill=C["goal"] if hit else C["label"])
        if lb.get("number") and (hit or v.s >= 8):
            text(d, str(lb["number"]), X + 8, Y - 8, C["goal"] if hit else C["label"], 14 if hit else 12, hit)
    if st.get("goal"):
        X, Y = v.px(st["goal"][0], st["goal"][1])
        r = 8 * k
        d.line([(X - r, Y - r), (X + r, Y + r)], fill=C["goal"], width=3)
        d.line([(X + r, Y - r), (X - r, Y + r)], fill=C["goal"], width=3)
        d.ellipse([X - 1.4 * r, Y - 1.4 * r, X + 1.4 * r, Y + 1.4 * r], outline=C["goal"], width=3)
    if st.get("pose"):
        x, y, _, yaw = st["pose"]
        X, Y = v.px(x, y)
        g = 1.3 * k
        pts = [(14, 0), (-9, 8), (-5, 0), (-9, -8)]
        d.polygon([(X + g * (px * math.cos(yaw) - py * math.sin(yaw)), Y - g * (px * math.sin(yaw) + py * math.cos(yaw)))
                   for px, py in pts], fill=C["robot"], outline=C["panel"], width=2)
    bar = 10 ** math.ceil(math.log10(60 / v.s))           # scale bar
    d.line([(v.W - 20 - bar * v.s, v.H - 16), (v.W - 20, v.H - 16)], fill=C["text"], width=3)
    text(d, "%g m" % bar, v.W - 20 - bar * v.s, v.H - 38, C["text"], 13)
    return np.asarray(im)


def draw_panel(W, H, st, t_rel, speed):
    im = Image.new("RGB", (W, H), C["panel"])
    d = ImageDraw.Draw(im)
    d.line([(0, 0), (0, H)], fill=C["line"], width=1)
    viz = st.get("_viz") or {}
    reg, fin = viz.get("registry") or {}, viz.get("finder") or {}
    x, y = 18, 12
    text(d, "Room Finder", x, y, C["text"], 20, True, False)
    y += 36
    state = fin.get("state") or "–"
    if state == "DONE":
        state = "찾음" if fin.get("found") else "포기"
    rows = [("목표 호실", str(fin.get("target", "–")), 22, True), ("상태", state, 15, state in ("찾음", "포기")),
            ("경과", "%d s" % fin["elapsed"] if fin.get("elapsed") is not None else "–", 15, False),
            ("이동 거리", "%s m" % fin["path_len"] if fin.get("path_len") is not None else "–", 15, False)]
    for k_, v_, sz, b in rows:
        text(d, k_, x, y + (5 if sz > 16 else 1), C["muted"], 13, False, False)
        col = C["label"] if v_ == "찾음" else C["goal"] if v_ == "포기" else C["text"]
        text(d, v_, x + 92, y, col, sz, b, False)
        y += sz + 14
    for k_, key in (("현재 목표", "item"), ("힌트", "hint")):
        text(d, k_, x, y, C["muted"], 13, False, False)
        for ln in wrap(str(fin.get(key) or "–"), font(13), W - x - 92 - 12)[:3]:
            text(d, ln, x + 92, y, C["text"], 13, False, False)
            y += 19
        y += 6
    y += 6
    text(d, "찾은 호수", x, y, C["muted"], 13, True, False)
    y += 24
    nums = sorted({str(lb["number"]) for lb in (reg.get("labels") or []) if lb.get("number")})
    cx = x
    for n in nums:
        f = font(12, n == str(fin.get("target")))
        w = int(f.getlength(n)) + 14
        if cx + w > W - 12:
            cx, y = x, y + 24
        if y > H * 0.62:
            break
        hit = n == str(fin.get("target"))
        d.rounded_rectangle([cx, y, cx + w, y + 19], radius=8, outline=C["goal"] if hit else C["line"])
        d.text((cx + 7, y + 1), n, fill=C["goal"] if hit else C["text"], font=f)
        cx += w + 5
    y += 32
    text(d, "문 %d · 호수 판 %d · 표지판 %d" % (len(reg.get("doors") or []), len([lb for lb in (reg.get("labels") or []) if lb.get("number")]),
                                          len([s for s in (reg.get("signs") or []) if not s.get("dead")])), x, y, C["muted"], 13, False, False)
    y += 30
    text(d, "로그", x, y, C["muted"], 13, True, False)
    y += 22
    lines = []
    for ln in (fin.get("log") or [])[-8:]:
        lines += wrap(ln if isinstance(ln, str) else json.dumps(ln), font(11), W - x - 12)
    for ln in lines[-max(1, int((H - 60 - y) / 16)):]:
        text(d, ln, x, y, C["muted"], 11, False, False)
        y += 16
    text(d, "t = %d s · 재생 x%g" % (t_rel, speed), x, H - 30, C["text"], 13, True, False)
    return np.asarray(im)


class Writer:
    def __init__(self, path, W, H, fps):
        ff = shutil.which("ffmpeg")
        self.p = self.w = None
        if ff and path.endswith(".mp4"):
            self.p = subprocess.Popen([ff, "-loglevel", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", "%dx%d" % (W, H),
                                       "-r", str(fps), "-i", "-", "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
                                       "-pix_fmt", "yuv420p", "-movflags", "+faststart", path], stdin=subprocess.PIPE)
        else:
            self.w = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*"mp4v"), fps, (W, H))
        self.codec = "H.264 (ffmpeg)" if self.p else "MPEG-4 part 2 (OpenCV)"

    def write(self, rgb):
        if self.p:
            self.p.stdin.write(np.ascontiguousarray(rgb).tobytes())
        else:
            self.w.write(cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR))

    def close(self):
        if self.p:
            self.p.stdin.close()
            self.p.wait()
        else:
            self.w.release()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--gw", required=True, help="gateway log folder (<robot PC ws>/log/room_finder_net/gateway/<time>)")
    ap.add_argument("--run", default="", help="ai_main run folder (<ws>/log/room_finder_net/<time>_T<target>) with debug_image/")
    ap.add_argument("--out", default="", help="output .mp4 (or .png with --still); default <run or gw>/video.mp4")
    ap.add_argument("--layout", choices=("both", "map", "cams"), default="", help="default: both with --run, else map")
    ap.add_argument("--view", choices=("fit", "follow"), default="fit")
    ap.add_argument("--scale", type=float, default=25.0, help="px per m for --view follow")
    ap.add_argument("--speed", type=float, default=8.0, help="playback speed (x real time)")
    ap.add_argument("--fps", type=float, default=15.0)
    ap.add_argument("--from", dest="t_from", type=float, default=0.0, help="start, s after the default start")
    ap.add_argument("--to", dest="t_to", type=float, default=None, help="end, s after the default start")
    ap.add_argument("--still", default="", help="write one PNG instead: 'end' or seconds after the start")
    ap.add_argument("--width", type=int, default=1920)
    ap.add_argument("--height", type=int, default=1080)
    a = ap.parse_args()

    S, viz, last_fin = [], None, {}
    for line in open(os.path.join(a.gw, "state.jsonl")):
        try:
            st = json.loads(line)
        except ValueError:
            continue
        if st.get("viz") is not None:
            viz = st["viz"]
            fin = viz.get("finder")
            if fin:     # the finder's last state (DONE) leaves out elapsed / path length / log: keep the last ones shown
                last_fin = {**last_fin, **{k_: v_ for k_, v_ in fin.items() if v_ not in (None, [], "")}}
                viz = {**viz, "finder": {**fin, **{k_: last_fin[k_] for k_ in ("elapsed", "path_len", "log", "item", "hint")
                                                   if fin.get(k_) in (None, [], "") and k_ in last_fin}}}
        st["_viz"] = viz
        S.append(st)
    if not S:
        sys.exit("no states in %s" % a.gw)
    ts = [st["t"] for st in S]
    maps = Maps(a.gw)
    frames = []                                   # (robot PC time, jpg)
    if a.run:
        fc = os.path.join(a.run, "debug_image", "frames.csv")
        if os.path.exists(fc):
            for row in csv.DictReader(open(fc)):
                frames.append((float(row["t_robot"]), os.path.join(a.run, "debug_image", row["file"])))
        frames.sort()
    fts = [f[0] for f in frames]
    layout = a.layout or ("both" if frames else "map")
    if layout != "map" and not frames:
        sys.exit("--layout %s needs --run with debug_image/frames.csv (ai_main --log-debug-hz)" % layout)

    fin_t = [st["t"] for st in S if (st["_viz"] or {}).get("finder")]
    t0 = max(frames[0][0], S[0]["t"]) if frames else (fin_t[0] if fin_t else S[0]["t"])
    t1 = min(frames[-1][0], S[-1]["t"]) if frames else S[-1]["t"]
    done = [st["t"] for st in S if ((st["_viz"] or {}).get("finder") or {}).get("state") == "DONE" and st["t"] > t0]
    if done:
        t1 = min(t1, done[0] + 8.0)
    t_end = t1
    t1 = min(t1, t0 + a.t_to) if a.t_to is not None else t1
    t0 = t0 + a.t_from

    W, H = a.width, a.height
    cam_h = int(round(W / 4.0)) if layout == "both" else 0       # the 8082 strip is 4:1 (three 4:3 tiles)
    panel_w = 0 if layout == "cams" else 360
    mw, mh = W - panel_w, H - cam_h
    poses = [(st["t"], st["pose"][0], st["pose"][1]) for st in S if st.get("pose")]
    pts = [(p[1], p[2]) for p in poses if t0 <= p[0] <= t_end]
    for st in S[bisect.bisect_left(ts, t_end) - 1:][:1]:
        reg = (st["_viz"] or {}).get("registry") or {}
        pts += [(o["x"], o["y"]) for k_ in ("doors", "labels", "signs") for o in reg.get(k_) or []]
    view = fit_view(mw, mh, maps.at(t_end)[0], pts) if layout != "cams" else None
    cache = {"k": None, "img": None}

    def frame(t):
        i = max(0, bisect.bisect_right(ts, t) - 1)
        st = S[i]
        out = np.empty((H, W, 3), np.uint8)
        out[:] = C["bg"]
        if layout != "cams":
            v = view
            if a.view == "follow" and st.get("pose"):
                v = View(mw, mh, st["pose"][0], st["pose"][1], a.scale)
            m, k = maps.at(t)
            if a.view == "follow" or cache["k"] != k:
                cache["k"], cache["img"] = k, v.raster(m)
            trail = [(x, y) for tt, x, y in poses if t0 - 1e-6 <= tt <= t]
            out[:mh, :mw] = draw_map(cache["img"].copy(), v, st, trail)
            out[:mh, mw:] = draw_panel(panel_w, mh, st, t - t0, a.speed)
        if layout != "map":
            j = max(0, bisect.bisect_right(fts, t) - 1)
            im = cv2.imread(frames[j][1])
            if im is not None:
                hh = cam_h or H
                im = cv2.resize(im, (W, int(round(im.shape[0] * W / im.shape[1]))), interpolation=cv2.INTER_AREA)[:hh]
                out[H - im.shape[0]:, :] = cv2.cvtColor(im, cv2.COLOR_BGR2RGB)
        return out

    base = a.run or a.gw
    if a.still:
        t = t1 if a.still == "end" else t0 + float(a.still)
        out = a.out or os.path.join(base, "map_%s.png" % a.still)
        Image.fromarray(frame(t)).save(out)
        print("wrote %s (t = %.0f s)" % (out, t - t0))
        return
    out = a.out or os.path.join(base, "video.mp4")
    wr = Writer(out, W, H, a.fps)
    n = int((t1 - t0) * a.fps / a.speed) + 1
    print("%s: %d frames, %.0f s of run at x%g -> %.0f s video, %s" % (out, n, t1 - t0, a.speed, n / a.fps, wr.codec))
    for k in range(n):
        wr.write(frame(t0 + k * a.speed / a.fps))
        if k % 100 == 0:
            print("  %d / %d" % (k, n), flush=True)
    wr.close()
    print("wrote", out)


if __name__ == "__main__":
    main()
