"""VLM landmark choice for the room finder (ReasonNav style): the VLM gets images as context and answers which candidate to
go to, with its reasons.

Images sent: (1) an overview map with numbered candidate goals, (2..) the raw photos of the directional signs seen so far.
Nothing is pre-parsed into directions: the VLM reads the signs itself; we only tell it which way a person reading the sign faces.
"""
import math

import cv2
import numpy as np

from mm_dev.room_finder import roomno

COMPASS = ("east", "north-east", "north", "north-west", "west", "south-west", "south", "south-east")


def compass(yaw):
    return COMPASS[int(round((yaw % (2 * math.pi)) / (math.pi / 4))) % 8]


def render_overview(gm, reg, cands, robot, target, max_px=1000):
    """Top-down map (+x right, +y up) with the landmarks and the numbered candidate goals. gm: GridMap-like (occ/free/unk, x0, y0, res)."""
    known = gm.occ | gm.free
    rr, cc = np.nonzero(known)
    if rr.size == 0:
        return None
    pts_x = [gm.x0 + (cc.min() - 8) * gm.res, gm.x0 + (cc.max() + 8) * gm.res, robot[0]] + [c["xy"][0] for c in cands]
    pts_y = [gm.y0 + (rr.min() - 8) * gm.res, gm.y0 + (rr.max() + 8) * gm.res, robot[1]] + [c["xy"][1] for c in cands]
    x0, x1, y0, y1 = min(pts_x) - 1.0, max(pts_x) + 1.0, min(pts_y) - 1.0, max(pts_y) + 1.0
    s = min(max_px / (x1 - x0), max_px * 0.8 / (y1 - y0))          # px per metre
    W, H = int((x1 - x0) * s), int((y1 - y0) * s)
    img = np.full((gm.h, gm.w, 3), 110, np.uint8)
    img[gm.free] = (238, 238, 238)
    img[gm.occ] = (25, 25, 25)
    M = np.array([[gm.res * s, 0, (gm.x0 - x0) * s], [0, -gm.res * s, (y1 - gm.y0) * s]], np.float32)
    out = cv2.warpAffine(img, M, (W, H), flags=cv2.INTER_NEAREST, borderValue=(110, 110, 110))
    P = lambda x, y: (int((x - x0) * s), int((y1 - y) * s))  # noqa: E731
    font = cv2.FONT_HERSHEY_SIMPLEX
    for lb in reg.get("labels", []):
        num = lb.get("number")
        txt, col = (num, (40, 150, 40)) if num else ((max((a for a, _ in lb["reads"]), key=[a for a, _ in lb["reads"]].count) + "?") if lb["reads"] else "?", (130, 130, 130))
        cv2.putText(out, txt, P(lb["x"], lb["y"]), font, 0.5, col, 1, cv2.LINE_AA)
    for sg in reg.get("signs", []):
        if sg.get("dead"):
            continue
        c = P(sg["x"], sg["y"])
        cv2.circle(out, c, 7, (0, 140, 255), -1)
        cv2.putText(out, "S%d" % sg["id"], (c[0] + 8, c[1] - 6), font, 0.5, (0, 110, 220), 1, cv2.LINE_AA)
    for d in reg.get("doors", []):
        c = P(d["x"], d["y"])
        cv2.rectangle(out, (c[0] - 3, c[1] - 3), (c[0] + 3, c[1] + 3), (160, 160, 160), 1)
    for c in cands:
        p = P(*c["xy"])
        cv2.circle(out, p, 14, (200, 90, 20), -1)
        cv2.putText(out, str(c["id"]), (p[0] - 8 * len(str(c["id"])), p[1] + 6), font, 0.6, (255, 255, 255), 2, cv2.LINE_AA)
    r = P(robot[0], robot[1])
    cv2.circle(out, r, 9, (0, 0, 220), -1)
    cv2.arrowedLine(out, r, (r[0] + int(30 * math.cos(robot[2])), r[1] - int(30 * math.sin(robot[2]))), (0, 0, 220), 3, tipLength=0.4)
    cv2.putText(out, "N", (W - 34, 24), font, 0.8, (0, 0, 0), 2, cv2.LINE_AA)
    cv2.arrowedLine(out, (W - 20, 60), (W - 20, 30), (0, 0, 0), 2, tipLength=0.4)
    return out


def describe_candidate(c, robot, reg):
    dx, dy = c["xy"][0] - robot[0], c["xy"][1] - robot[1]
    dist = math.hypot(dx, dy)
    near = [lb["number"] for lb in reg.get("labels", []) if lb.get("number") and math.hypot(lb["x"] - c["xy"][0], lb["y"] - c["xy"][1]) < 6.0]
    s = "#%d  %s  (%.0f m %s of the robot)" % (c["id"], c["note"], dist, compass(math.atan2(dy, dx)))
    if near:
        s += "; plates nearby: " + ", ".join(sorted(set(near))[:6])
    return s


def build_prompt(target, cands, robot, reg, sign_images, check=True, table=True, steps=True):
    """sign_images: [(sign dict, ndarray)] in the order the images are attached after the map."""
    lines = ["A mobile robot is searching a hospital for room %s. You decide where it goes next." % target, "",
             "Attached images, in this order:",
             "1. Overview map seen from above (up = north, right = east). Grey = unexplored, white = free floor, black = walls. "
             "Red arrow = the robot. Numbered blue discs = the candidate goals you may choose. Orange S# = directional signs the robot has "
             "seen. Green numbers = room plates already read, grey ones with '?' = unconfirmed reads."]
    for i, (sg, _) in enumerate(sign_images, start=2):
        n = sg.get("n")
        face = compass(math.atan2(-n[1], -n[0])) if n else "unknown direction"
        lines.append("%d. Photo of directional sign S%d (it is at map position (%.0f, %.0f)). A person reading this sign stands in front of it "
                     "and faces %s on the map." % (i, sg["id"], sg["x"], sg["y"], face))
        if n and table:
            fy = math.atan2(-n[1], -n[0])
            lines.append("   Arrow-to-map table for this sign (computed): arrow pointing UP = %s, LEFT = %s, RIGHT = %s, DOWN = %s. "
                         "Only identify which arrow the photo shows; use this table to get the map direction." %
                         (compass(fy), compass(fy + math.pi / 2), compass(fy - math.pi / 2), compass(fy + math.pi)))
        if not check:
            continue
        tp = roomno.parse(target)
        hit = [c["place"] for c in sg.get("cues", []) if tp and c.get("lo") is not None and (c.get("pre") or "") == tp[0] and c["lo"] <= tp[1] <= c["hi"]]
        lines.append("   Number check done by the program (exact arithmetic, from a transcription of this photo): entries whose room range contains %s: %s."
                     " Look at that entry's arrow in the photo." % (target, "; ".join(hit) if hit else "none found"))
    lines += ["",
              "Reading a sign: an arrow is drawn for a person who stands in front of the sign and looks at it. 'Up' means straight ahead "
              "(the direction that person faces), 'left'/'right' are to that person's left/right, 'down' means turn around. Translate each "
              "arrow into a map direction yourself. Room numbers are 4-digit; a place such as 'Support Area 3015~3024' covers that range.",
              "", "Robot is at (%.0f, %.0f) facing %s." % (robot[0], robot[1], compass(robot[2])), "", "Candidates:"]
    lines += [describe_candidate(c, robot, reg) for c in cands]
    known = sorted((lb["number"], lb["x"], lb["y"]) for lb in reg.get("labels", []) if lb.get("number"))
    if known:
        lines += ["", "Plates read so far (number at map position): " + "; ".join("%s (%.0f, %.0f)" % k for k in known[:30])]
    if steps:
        lines += ["", "Task: choose ONE candidate that is most likely to lead to room %s. Work in these steps:" % target,
                  "Step 1. On each sign photo, find the entry whose room range contains %s (compare the numbers digit by digit; a range such as "
                  "3015~3024 contains 3022, but 3025~3039 does not). If no entry contains it, say so." % target,
                  "Step 2. Turn that entry's arrow into a map direction (north/east/south/west...) using the way the person faces the sign.",
                  "Step 3. Use the plate numbers already read: numbers close to %s show which area is near it." % target,
                  "Step 4. Pick the candidate that lies in the direction found in steps 2-3, and say why the main alternatives are worse.",
                  'Answer with JSON only: {"sign_entry": "<entry containing the room or null>", "map_direction": "<direction or null>", '
                  '"choice": <candidate number>, "reason": "<2-4 sentences>"}']
    else:
        lines += ["", "Task: choose ONE candidate that is most likely to lead to room %s. Use the signs and the plate numbers. "
                  "Explain the choice: which sign text and arrow, or which plate numbers, support it, and why the main alternatives are worse." % target,
                  'Answer with JSON only: {"choice": <candidate number>, "reason": "<2-4 sentences>"}']
    return "\n".join(lines)


def paper_prompt(target, labels, robot, extent, regions=("right", "left", "up", "down"), signs=None):
    """Text-only query in the style of 'Follow the Signs' (Cao, Kumar, Curtis): semantic grid -> patterns -> goal region.
    labels: [(number, x, y)] read so far; robot: (x, y, yaw); extent: (xmin, xmax, ymin, ymax) of the explored area."""
    rows = "\n".join("  room %s at x=%.0f, y=%.0f" % (n, x, y) for n, x, y in sorted(labels))
    sign_txt = ""
    if signs:
        sign_txt = "Directional signs read so far (each entry: place, and the map direction its arrow points to, as computed from the photo):\n" + "\n".join(
            "  sign at x=%.0f, y=%.0f: " % (s["x"], s["y"]) + "; ".join("'%s' -> %s" % (e["place"], e["compass"]) for e in s["entries"]) for s in signs) + "\n"
    return (f"A robot searches a hospital floor for room {target}. Map coordinates: x grows to the right (east), y grows up (north).\n"
            f"Robot position: x={robot[0]:.0f}, y={robot[1]:.0f}. Explored area: x from {extent[0]:.0f} to {extent[1]:.0f}, y from {extent[2]:.0f} to {extent[3]:.0f}.\n"
            f"Room numbers read so far (number and position):\n{rows or '  (none yet)'}\n{sign_txt}\n"
            "1. Describe your reasoning. 2. State the patterns you infer from the numbers and positions (numbering direction along hallways, "
            "odd/even sides, wings, where numbering wraps around). 3. Predict in which direction relative to the robot room "
            f"{target} most likely is: one of {', '.join(regions)} (right/east = +x, up/north = +y).\n"
            'Answer with JSON only: {"reasoning": "...", "patterns": "...", "region": "' + "|".join(regions) + '"}')


def in_region(region, robot, xy):
    dx, dy = xy[0] - robot[0], xy[1] - robot[1]
    return {"right": dx > 0, "left": dx < 0, "up": dy > 0, "down": dy < 0}.get(region, False)


def render_belief_map(snap, reg, robot, signs, max_px=1000, conf=None, grid=False, openings=None):
    """Map picture for the belief query (as in the paper's grid figures): wall / free / unexplored, the area the robot has already
    looked at (tinted), the room numbers read so far, the robot and, for every sign photo sent, where the sign is and where the robot
    stood / looked when the photo was taken. +x is right, +y is up (north)."""
    occ, free, looked = snap["occ"], snap["free"], snap["looked"] > 0
    rr, cc = np.nonzero(occ | free)
    if rr.size == 0:
        return None
    res, x0g, y0g = snap["res"], snap["x0"], snap["y0"]
    xs = [x0g + (cc.min() - 6) * res, x0g + (cc.max() + 6) * res, robot[0]] + [s["vx"] for s in signs] + [s["x"] for s in signs]
    ys = [y0g + (rr.min() - 6) * res, y0g + (rr.max() + 6) * res, robot[1]] + [s["vy"] for s in signs] + [s["y"] for s in signs]
    x0, x1, y0, y1 = min(xs) - 1.0, max(xs) + 1.0, min(ys) - 1.0, max(ys) + 1.0
    s_px = min(max_px / (x1 - x0), max_px * 0.85 / (y1 - y0))
    W, H = int((x1 - x0) * s_px), int((y1 - y0) * s_px)
    img = np.full(occ.shape + (3,), 150, np.uint8)                      # unexplored
    if conf is None:
        img[free] = (250, 250, 250)
        img[free & looked] = (255, 225, 190)                           # looked at by the robot (BGR light blue)
    else:                                                                # confidence grid as a heat map (the paper's figure)
        mx = float(conf.max())
        heat = cv2.applyColorMap((np.clip(conf / mx, 0, 1) * 255).astype(np.uint8) if mx > 1e-6 else np.zeros(conf.shape, np.uint8), cv2.COLORMAP_PLASMA)
        img[free] = heat[free]
        img[:] = np.where((free | occ)[..., None], img, 90)
    img[occ] = (20, 20, 20)
    M = np.array([[res * s_px, 0, (x0g - x0) * s_px], [0, -res * s_px, (y1 - y0g) * s_px]], np.float32)
    out = cv2.warpAffine(img, M, (W, H), flags=cv2.INTER_NEAREST, borderValue=(150, 150, 150))
    P = lambda x, y: (int((x - x0) * s_px), int((y1 - y) * s_px))  # noqa: E731
    font = cv2.FONT_HERSHEY_SIMPLEX
    if grid:    # coordinate lines every 10 m, labelled in map metres, so the VLM can name a position
        for gx in range(int(math.ceil(x0 / 10.0)) * 10, int(x1) + 1, 10):
            cv2.line(out, P(gx, y0), P(gx, y1), (200, 120, 0), 1)
            cv2.putText(out, "x=%d" % gx, (P(gx, y0)[0] + 3, H - 38), font, 0.45, (200, 120, 0), 1, cv2.LINE_AA)
        for gy in range(int(math.ceil(y0 / 10.0)) * 10, int(y1) + 1, 10):
            cv2.line(out, P(x0, gy), P(x1, gy), (200, 120, 0), 1)
            cv2.putText(out, "y=%d" % gy, (4, P(x0, gy)[1] - 3), font, 0.45, (200, 120, 0), 1, cv2.LINE_AA)
    for lb in reg.get("labels", []):
        num = lb.get("number")
        if num:
            cv2.putText(out, num, P(lb["x"], lb["y"]), font, 0.55, (30, 140, 30), 2, cv2.LINE_AA)
        elif lb.get("reads"):
            guess = max((a for a, _ in lb["reads"]), key=[a for a, _ in lb["reads"]].count)
            cv2.putText(out, guess + "?", P(lb["x"], lb["y"]), font, 0.45, (110, 110, 110), 1, cv2.LINE_AA)
    for k, sg in enumerate(signs, start=1):
        a, b = P(sg["vx"], sg["vy"]), P(sg["x"], sg["y"])
        cv2.arrowedLine(out, a, b, (0, 120, 255), 2, tipLength=0.15)
        cv2.circle(out, b, 7, (0, 120, 255), -1)
        cv2.putText(out, "photo %d" % k, (b[0] + 8, b[1] - 8), font, 0.55, (0, 90, 220), 2, cv2.LINE_AA)
    for L, ox, oy in openings or []:     # openings into unexplored space, lettered so the VLM can name the one to drive through
        o = P(ox, oy)
        cv2.circle(out, o, 8, (200, 0, 200), -1)
        cv2.putText(out, L, (o[0] + 9, o[1] + 6), font, 0.7, (200, 0, 200), 2, cv2.LINE_AA)
    r = P(robot[0], robot[1])
    cv2.circle(out, r, 9, (0, 0, 220), -1)
    cv2.arrowedLine(out, r, (r[0] + int(30 * math.cos(robot[2])), r[1] - int(30 * math.sin(robot[2]))), (0, 0, 220), 3, tipLength=0.4)
    # north arrow, 10 m scale bar and legend
    cv2.arrowedLine(out, (W - 24, 64), (W - 24, 30), (0, 0, 0), 2, tipLength=0.35)
    cv2.putText(out, "N", (W - 34, 24), font, 0.8, (0, 0, 0), 2, cv2.LINE_AA)
    cv2.line(out, (12, H - 14), (12 + int(10 * s_px), H - 14), (0, 0, 0), 3)
    cv2.putText(out, "10 m", (16, H - 22), font, 0.5, (0, 0, 0), 1, cv2.LINE_AA)
    legend = (("black = wall, white = free floor, grey = unexplored", "light blue = already looked at by the robot",
               "green number = room plate read, grey ? = unconfirmed", "red arrow = robot") + ((("magenta letter = opening into unexplored space",) if openings else ())) if conf is None else
              ("CONFIDENCE MAP: yellow = most likely to hold the goal (from your earlier guesses, fading over time)", "dark purple = no evidence, black = wall, grey = unexplored",
               "cells the robot has already looked at were reset to zero", "red arrow = robot"))
    for i, t in enumerate(legend):
        cv2.putText(out, t, (12, 20 + 18 * i), font, 0.45, (255, 255, 255) if conf is not None else (0, 0, 0), 1, cv2.LINE_AA)
    return out


def plate_order(target, labels, tentative=None, max_gap=15.0):
    """observed facts for the prompt, no rule applied: the plates of the target's series in number order, and for neighbours less
    than max_gap apart (the same hallway) the step between them: which way the numbers grow along that hallway"""
    tp = roomno.parse(target)
    if tp is None:
        return []
    pts = {}
    for n, x, y in list(labels) + list(tentative or []):
        p = roomno.parse(n)
        if p is not None and p[0] == tp[0] and n not in pts:
            pts[n] = (p[1], x, y)
    seq = sorted(pts.items(), key=lambda kv: kv[1][0])
    out = []
    for (na, (_, xa, ya)), (nb, (_, xb, yb)) in zip(seq, seq[1:]):
        d = math.hypot(xb - xa, yb - ya)
        if 0.5 < d < max_gap:
            out.append("  %s (x=%.0f, y=%.0f) -> %s (x=%.0f, y=%.0f): %.0f m to the %s" % (na, xa, ya, nb, xb, yb, d, compass(math.atan2(yb - ya, xb - xa))))
    return out


def belief_prompt_images(target, labels, robot, signs, regions, with_conf=False, guide=False, prev=None, point=False, tentative=None, openings=None):
    """Prompt for the picture-based belief query. signs: [{id, x, y, vx, vy, heading_deg, heading_word}] in the order of the photos."""
    lines = ["A robot searches a hospital floor for room %s. Map coordinates in metres: x grows to the right (east), y grows up (north)." % target,
             "Robot position: x=%.0f, y=%.0f." % (robot[0], robot[1]), "",
             "Attached images, in this order:",
             "1. Map of what the robot has explored so far (north is up). Black = walls, white = free floor, grey = not explored yet, light blue = "
             "areas the robot has already looked at (the goal room was not found there). Green numbers are room plates that were read; the red arrow "
             "is the robot." + (" Magenta letters (A, B, ...) mark the openings into unexplored space that the robot can drive to." if openings else "")]
    first = 2
    if with_conf:
        lines.append("2. Confidence map of the same area, same view: where your earlier predictions say the goal most likely is (yellow = most likely, dark purple "
                     "= no evidence). Predictions fade over time, and cells the robot has already looked at are reset to zero. It is empty at the start.")
        first = 3
    for k, s in enumerate(signs, start=first):
        lines.append("%d. Photo of a directional sign ('photo %d' on the map). The sign is at map position (%.0f, %.0f). The robot took the photo from about "
                     "(%.0f, %.0f), looking toward the %s (map angle %.0f deg, measured from +x counter-clockwise); on the map this is the arrow labelled "
                     "'photo %d'. An arrow printed on the sign is drawn for someone standing there and looking at it: 'up' is straight ahead (along that "
                     "map arrow), 'left'/'right' are to that person's left/right, 'down' is back toward the person." %
                     (k, k - first + 1, s["x"], s["y"], s["vx"], s["vy"], s["heading_word"], s["heading_deg"], k - first + 1))
    rows = "\n".join("  room %s at x=%.0f, y=%.0f" % (n, x, y) for n, x, y in sorted(labels))
    if guide:
        lines += ["", "How to read the evidence:",
                  "- A sign lists several ranges, each with its own arrow. An entry whose range contains %s tells you where it is, and that is certain: go the way "
                  "THAT arrow points (turn it into a map direction with the viewing direction of the photo). An entry whose range does not contain %s makes that way "
                  "less likely, but it does not rule it out: a sign does not list every room. Weigh it against the plate numbers read so far." % (target, target),
                  "- Use the room plates read so far to find which way the numbers increase along each hallway and on which side the odd / even numbers are; if %s is "
                  "beyond the lowest or highest plate in a hallway, it lies further along that hallway." % target,
                  "- Prefer the strongest evidence (a sign entry covering %s, or plates close to %s). If your earlier answers disagree with it, correct them." % (target, target)]
        if openings is not None:
            lines += ["- A directional sign normally stands at or near the entrance of the hallway its arrows lead into. Turn the arrow of the entry covering %s into a "
                      "map direction, then take the nearest hallway entrance or lettered opening in that direction from the sign (usually within about 10 m of it). "
                      "The arrow shows the first leg only: a sign beside a hallway entrance points at that entrance, and the hallway behind it may run "
                      "sideways (e.g. an arrow to the north toward an entrance 2 m away, the hallway then running west). Do not put goal_xy far along "
                      "the arrow line into the open lobby; put it inside the hallway that starts at that entrance, where its plate numbers grow toward %s. "
                      "The room is inside that hallway, not in the open lobby: put goal_xy at least 10 m inside the hallway (further than the last plate read in it) "
                      "and never put a not_here circle on that hallway or its entrance." % (target, target),
                      "- The viewing direction of a photo is estimated and can be off by up to 45 deg. Plates whose numbers are close to %s that were read inside a "
                      "hallway are stronger evidence than an arrow: if the two disagree, follow the plates into that hallway, toward where the numbers approach %s." % (target, target)]
        if prev:
            lines.append("- Your earlier predictions (robot position -> direction): " + "; ".join("(%.0f, %.0f) -> %s" % (x, y, r) for r, x, y in prev[-4:]))
    if tentative:
        rows += "\n" + "\n".join("  tentative: room %s at x=%.0f, y=%.0f (a single read, digits may be wrong)" % (n, x, y) for n, x, y in tentative)
    if openings:
        lines += ["", "Openings into unexplored space the robot can drive to (magenta letters on the maps):"] + ["  %s at x=%.0f, y=%.0f" % o for o in openings]
    order = plate_order(target, labels, tentative) if guide else []
    if order:
        rows += ("\n\nPlates of the %s series in number order, consecutive ones less than 15 m apart (same hallway), with the direction of "
                 "the step -- the numbers grow in that direction along that hallway:\n" % roomno.parse(target)[0]) + "\n".join(order)
    lines += ["", "Room numbers read so far (number and position):", rows or "  (none yet)", "",
              "1. Describe your reasoning. 2. State the patterns you infer from the numbers, positions and signs (numbering direction along hallways, odd/even "
              "sides, wings, where numbering wraps around, which sign entry covers the target). 3. Predict in which direction relative to the robot room %s most "
              "likely is: one of %s (right/east = +x, up/north = +y)." % (target, ", ".join(regions)),
              'Answer with JSON only: {"reasoning": "...", "patterns": "...", "region": "' + "|".join(regions) + '"}']
    if point:
        lines[-2] += (" 4. Also give goal_xy: the map position [x, y] in metres where you think room %s is (the maps carry blue grid lines every 10 m labelled x=.. / y=..; "
                      "the position may lie in the unexplored grey area, e.g. along the hallway a sign points into, further than the last plate read; never "
                      "inside the light-blue area the robot has already looked at). "
                      "5. Also give not_here: up to 4 circles [x, y, radius_m] around places that cannot hold room %s because the plates read there show a "
                      "different number range (e.g. the hallway of plates T132 / T133 when the target is far below them); [] if none. A sign entry that does not "
                      "list %s is no reason for a not_here circle: it makes that way less likely, not impossible. "
                      "If no plate and no sign entry gives usable evidence about where %s is, do NOT guess: answer region 'unknown', goal_xy null and not_here []." % (target, target, target, target))
        lines[-1] = lines[-1][:-1] + ', "goal_xy": [x, y], "not_here": [[x, y, radius_m]]}'
        if openings:
            lines[-2] += (" 6. Also give via: the letter of the opening the robot should drive through toward goal_xy (the hallway entrance the evidence points to), or null."
                          " Answer null when no listed opening lies on the way to goal_xy; do not pick one only because it is the only one listed.")
            lines[-1] = lines[-1][:-1] + ', "via": "A"}'
    return "\n".join(lines)
