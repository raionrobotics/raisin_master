"""Reasoning panel of the search video (shared by room_recorder.py and rerender_video.py).

The panel shows what the VLM was asked and what it answered: the crops that were sent (thumbnails) next to the raw
answers, the parsed result, the finder's goal / hint / candidate scores and its recent log lines.
"""
import math

import cv2
import numpy as np

from mm_dev.room_finder import roomno

FONT = cv2.FONT_HERSHEY_SIMPLEX
PANEL_W, PANEL_H = 600, 600


def _put(img, text, x, y, scale=0.45, col=(230, 230, 230), th=1):
    cv2.putText(img, text, (x, y), FONT, scale, col, th, cv2.LINE_AA)


def _wrap(text, width):
    text = " ".join(str(text).split())
    return [text[i:i + width] for i in range(0, len(text), width)] or [""]


def _thumb(img, max_w, max_h):
    if img is None:
        return None
    h, w = img.shape[:2]
    s = min(max_w / w, max_h / h, 1.0 if max(w, h) <= max(max_w, max_h) else 9.0)
    s = min(max_w / w, max_h / h)
    return cv2.resize(img, (max(1, int(w * s)), max(1, int(h * s))), interpolation=cv2.INTER_AREA if s < 1 else cv2.INTER_CUBIC)


def _paste(dst, src, x, y):
    if src is None:
        return
    h, w = src.shape[:2]
    h = min(h, dst.shape[0] - y); w = min(w, dst.shape[1] - x)
    if h > 0 and w > 0:
        dst[y:y + h, x:x + w] = src[:h, :w]


def draw_reason_panel(ctx):
    """ctx: target (str), item, hint, cands [(note, score)] or None, log [str],
    reads [{number, conf, dist, source, raw, crop(ndarray|None)}] (oldest first),
    sign {sign, head_on, dist, cues, raw|None, crop(ndarray|None)} or None"""
    img = np.full((PANEL_H, PANEL_W, 3), 28, np.uint8)
    target = str(ctx.get("target", ""))
    _put(img, "Reasoning", 12, 24, 0.65, (255, 255, 255), 2)
    _put(img, "goal: %s" % (ctx.get("item") or "-"), 12, 48, 0.5, (120, 200, 255))
    _put(img, ("hint: %s" % ctx.get("hint", "-"))[:78], 12, 68, 0.4, (120, 255, 160))
    y = 88
    bl = ctx.get("belief")
    if bl:      # paper-style LLM answer: region, patterns, reasoning
        _put(img, "LLM (text only) -> goal region: %s" % bl.get("region"), 12, y, 0.42, (255, 200, 120)); y += 14
        for key in ("patterns", "reasoning"):
            for line in _wrap(bl.get(key, ""), 92)[:2 if key == "patterns" else 3]:
                _put(img, line, 12, y, 0.32, (190, 190, 190)); y += 12
    elif ctx.get("cands"):
        for note, sc in ctx["cands"][:3]:
            _put(img, "  %6.1f  %s" % (sc, note), 12, y, 0.38, (200, 200, 200)); y += 15
    y = max(y, 100) + 8
    # ---- plate crops and what the VLM answered
    _put(img, "VLM, plate crops (image sent -> answer):", 12, y, 0.45, (200, 200, 200)); y += 8
    for e in list(ctx.get("reads", []))[-3:]:
        th = _thumb(e.get("crop"), 120, 64)
        top = y
        if th is not None:
            _paste(img, th, 12, top)
        else:
            cv2.rectangle(img, (12, top), (132, top + 64), (60, 60, 60), 1)
        num = e.get("number")
        col = (120, 255, 160) if num and num == target else ((235, 235, 235) if num else (150, 150, 150))
        _put(img, "-> %s   conf %.2f   %.1f m  (%s)" % (num or "no number", e.get("conf", 0), e.get("dist", 0), e.get("source", "")), 144, top + 20, 0.43, col)
        raw = " ".join(str(e.get("raw") or "").replace("```json", "").replace("```", "").split())
        _put(img, "VLM: " + (raw[:54] if raw else "(answer not recorded)"), 144, top + 42, 0.36, (170, 170, 170))
        y = top + 70
    if not ctx.get("reads"):
        y += 4
    # ---- sign crop and its answer
    y += 6
    _put(img, "VLM, sign crop (image sent -> answer):", 12, y, 0.45, (200, 200, 200)); y += 8
    s = ctx.get("sign")
    if s:
        th = _thumb(s.get("crop"), 150, 118)
        if th is not None:
            _paste(img, th, 12, y)
        else:
            cv2.rectangle(img, (12, y), (162, y + 118), (60, 60, 60), 1)
        _put(img, "S%s  head-on %.0f deg  %.1f m" % (s.get("sign"), s.get("head_on", 0), s.get("dist", 0)), 172, y + 12, 0.4, (235, 235, 235))
        ty = y + 28
        if s.get("raw"):
            for line in _wrap(s["raw"], 48)[:7]:
                _put(img, line, 172, ty, 0.34, (170, 170, 170)); ty += 12
        else:      # answer text was not recorded for this video: show the parsed tuples
            _put(img, "(raw answer not recorded; parsed:)", 172, ty, 0.34, (150, 150, 150)); ty += 12
            for c in s.get("cues", [])[:7]:
                b = c.get("bearing")
                tp = roomno.parse(target)
                hit = c.get("lo") is not None and tp is not None and (c.get("pre") or "") == tp[0] and c["lo"] <= tp[1] <= c["hi"]
                _put(img, "%-22s %-9s %s" % (c.get("place", "")[:22], c.get("direction", ""), "" if b is None else "%+.0f" % math.degrees(b)),
                     172, ty, 0.34, (90, 90, 255) if hit else (215, 215, 215)); ty += 12
        y += 124
    else:
        y += 6
    # ---- finder log
    y = max(y + 4, 500)
    _put(img, "finder log:", 12, y, 0.42, (200, 200, 200)); y += 14
    for line in list(ctx.get("log", []))[-4:]:
        _put(img, line[:92], 12, y, 0.32, (175, 175, 175)); y += 13
    return img
