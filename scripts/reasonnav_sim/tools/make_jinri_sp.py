#!/usr/bin/env python3
"""Small-plate-text copy of raisin_raibo2/resource/jinri_1f/tools/make_jinri.py (worlds jinri_1f_sp, jinri_1f_clutter_sp).

Procedural raisim environment of KAIST Munji campus Jinri-gwan (진리관), 1st floor, built from the evacuation plan
photo (rooms T101-T146).  Writes visual.obj/.mtl + textures, collision.obj, jinri_1f.urdf next to this tools/ dir, the
world XML ../raisim_config/jinri_1f.xml and the ground truth (plate centres) for the room-finder harness.

    make_jinri.py [--gt ~/raisin_ws/scripts/reasonnav_sim/gt/jinri_1f_rooms.json] [--preview plan.png]

Geometry: plan pixels -> metres with x = (px - 900) * 0.09 (east), y north; the main corridor is y in [0, 2.4].  Corridor
widths are set to real-world values (2.4 m, inner east corridor 2.0 m) instead of the drawing's thin lines.  All rooms are
closed (doors are not openable); the robot moves in the corridors, halls and the lobby only.

Content per room door: frame + leaf + lever handle, a room plate (0.30 x 0.14 m, centre 1.55 m high) beside the door.
Directional signs: hanging double-sided corridor panels at junctions and wall strips like the real "<- T131~T150" ones.
Distractors: elevator, toilet and stair doors without numbers, fire hydrant cabinets, extinguishers, notice boards."""
import argparse
import json
import math
import os

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont
from shapely.geometry import Polygon, box
from shapely.geometry.polygon import orient
from shapely.ops import unary_union

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.expanduser("~/raisin_ws/install/resource/raisin_raibo2/resource/jinri_1f_sp")   # small-text copy: install tree only
WALL_H, CEIL_H = 2.7, 2.7
CW = 2.4   # corridor width
LINE_PX = 220   # sign line height at 2000 px/m

FONT_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_KR = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"


def X(px):
    return round((px - 900) * 0.09, 2)


# ------------------------------------------------------------------ layout (metres)
FREE = [
    (-60.1, 44.4, 0.0, CW),            # main corridor (west end hall -> vertical corridor junction)
    (-60.1, -55.8, -3.0, 10.0),        # west end hall (stairs, exits)
    (-13.4, 0.0, -6.5, 6.0),           # central lobby (dome added below), main entrance south
    (44.4, 49.6, -1.8, 5.1 - 2.7),     # south-east exit hall
    (42.0, 44.4, CW, 22.0),            # vertical (north-south) east corridor
    (44.4, 71.1, 12.6, 14.6),          # inner east corridor (T112-T115)
    (44.4, 49.6, 12.6, 17.0),          # landing between the vertical and inner corridors
    (9.6, 71.7, 19.6, 22.0),           # northern corridor
    (9.6, 25.8, 19.6, 30.0),           # north-west hall (open area on the plan)
    (32.7, 35.1, 22.0, 31.0),          # north exit corridor
]
DOME = (-6.7, 6.0, 5.0, 2.25)          # lobby dome: centre x, base y, half width, height


def free_space():
    polys = [box(x0, y0, x1, y1) for x0, x1, y0, y1 in FREE]
    cx, by, hw, hh = DOME
    t = np.linspace(0, math.pi, 25)
    polys.append(Polygon([(cx - hw, by - 0.1)] + [(cx - hw * math.cos(a), by + hh * math.sin(a)) for a in t] + [(cx + hw, by - 0.1)]))
    return orient(unary_union(polys).buffer(0), 1.0)


# rooms: number, wall the door is on (the corridor face), wall coordinate, span along the wall, door offsets along the
# span measured from its start (west or south end), kind label (Korean, small text under the number)
R = []


def row(nums_bounds, wall, coord, door_at="start", kind="강의실"):
    for num, a, b in nums_bounds:
        R.append(dict(num=num, wall=wall, coord=coord, a=a, b=b, door_at=door_at, kind=kind))


# main corridor, south side (doors in the y=0 wall, facing north)
row([("T140", -55.8, X(337)), ("T139", X(337), X(389)), ("T138", X(389), X(439)), ("T137", X(439), X(490)),
     ("T136", X(490), X(540)), ("T135", X(540), X(591)), ("T134", X(591), X(644)), ("T133", X(644), X(693)),
     ("T132", X(693), -13.4)], "S", 0.0, "start")
row([("T101", 0.0, X(957)), ("T102", X(957), X(1010)), ("T103", X(1010), X(1079)), ("T104", X(1079), X(1115)),
     ("T105", X(1115), X(1170)), ("T106", X(1170), X(1225)), ("T107", X(1225), X(1280)), ("T108", X(1280), X(1335)),
     ("T109", X(1335), 42.0)], "S", 0.0, "start")
# main corridor, north side (doors in the y=2.4 wall, facing south)
row([("T141", -55.8, X(331)), ("T142", X(331), X(382))], "N", CW, "end", "연구실")
row([("T143", X(382), X(485)), ("T144", X(485), X(588))], "N", CW, "both")
row([("T145", X(588), X(640)), ("T146", X(640), X(692))], "N", CW, "end", "연구실")
# east wing
row([("T110", 5.1, 9.9), ("T111", 9.9, 12.6)], "E", 44.4, "mid", "연구실")          # west wall of the east block
row([("T112", 49.6, X(1510)), ("T113", X(1510), X(1567)), ("T114", X(1567), X(1627)), ("T115", X(1627), 71.1)], "S", 12.6, "start")
row([("T121", 17.0, 19.6)], "E", 44.4, "mid", "연구실")
row([("T120", 49.6, X(1512)), ("T119", X(1512), X(1570))], "S", 19.6, "start", "연구실")
row([("T116~T118", X(1570), 71.1)], "S", 19.6, "both", "실험실")
row([("T127", 9.6, X(1117))], "S", 19.6, "start", "세미나실")
row([("T122", X(1117), 42.0)], "S", 19.6, "both", "대강의실")
row([("T128", X(1459), X(1517)), ("T129", X(1517), X(1577)), ("T130", X(1577), X(1637)), ("T131", X(1637), 71.7)], "N", 22.0, "start")

# doors without a room number: (x or y along the wall, wall, coord, kind)  kind: elevator | toilet_m | toilet_w | stair | plain | exit
EXTRA_DOORS = [
    (1.6, "N", CW, "elevator"), (5.0, "N", CW, "toilet_w"), (7.8, "N", CW, "toilet_m"),
    (-16.0, "N", CW, "stair"),
    (3.6, "E", 44.4, "toilet_m"),                      # toilet beside the vertical corridor
    (17.0, "W", 42.0, "plain_T122"),                   # T122 side door into the vertical corridor
    (29.3, "N", 22.0, "plain"), (40.0, "N", 22.0, "plain"),   # unnamed room north-west / big north room
    (-1.0, "S", -6.5, "exit"), (-4.5, "S", -6.5, "exit"),     # main entrance (south of the lobby)
    (-58.0, "S", -3.0, "exit"), (8.0, "W", -60.1, "exit"),    # west end exits
    (0.3, "E", 49.6, "exit"), (20.8, "E", 71.7, "exit"), (33.9, "N", 31.0, "exit"),
    (24.0, "N", 30.0, "exit"), (5.0, "W", -60.1, "stair"),
]

# directional signs.  hang: (x, y, axis 'x'|'y') double-sided panel hanging across a corridor at 2.15 m;
# wall: (x, y, wall normal yaw) single-sided.  entries: (text, world direction of the arrow: 'E','W','N','S','NE',...)
SIGNS = [
    dict(kind="hang", at=(17.0, 1.2), axis="x", faces={
        "+": [("T101~T104", "W"), ("T132~T146", "W")],          # face looking east (seen by a robot heading west)
        "-": [("T105~T109", "E"), ("T110~T131", "E")]}),
    dict(kind="hang", at=(39.5, 1.2), axis="x", faces={
        "+": [("T101~T108", "W"), ("T132~T146", "W")],
        "-": [("T109", "E"), ("T110~T131", "NE")]}),
    dict(kind="hang", at=(43.2, 9.0), axis="y", faces={
        "-": [("T110~T111", "E"), ("T112~T115", "NE"), ("T116~T131", "N"), ("T122  T127", "N")],
        "+": [("T101~T109", "S"), ("T132~T146", "S")]}),
    dict(kind="wall", at=(43.2, 22.0), yaw=-math.pi / 2, entries=[("T122  T127", "W"), ("T116~T121", "E"), ("T128~T131", "E")]),
    dict(kind="wall", at=(-12.5, 6.0), yaw=-math.pi / 2, entries=[("T132~T146", "W"), ("T101~T131", "E")]),
    dict(kind="hang", at=(-25.0, 1.2), axis="x", faces={
        "+": [("T101~T131", "E")],
        "-": [("T132~T146", "W")]}),
    # wall strips like the real ones (single entry, ~40 x 10 cm)
    dict(kind="strip", at=(-15.0, CW), yaw=-math.pi / 2, entries=[("T133~T146", "W")]),
    dict(kind="strip", at=(-36.3, CW), yaw=-math.pi / 2, entries=[("T132~T138", "E")], z=1.62),
    dict(kind="strip", at=(-36.3, CW), yaw=-math.pi / 2, entries=[("T139~T143", "W")], z=1.48),
    dict(kind="strip", at=(46.0, 14.6), yaw=-math.pi / 2, entries=[("T112~T115", "E")]),
    dict(kind="strip", at=(30.0, 22.0), yaw=-math.pi / 2, entries=[("T128~T131", "E")]),
    dict(kind="strip", at=(12.0, 0.0), yaw=math.pi / 2, entries=[("T101~T109", "W")], z=1.55),
    # the two lobby strips as in the real building: seen from the lobby, "<- T131~T150" right of the west corridor entrance and
    # "T101~T126 ->" left of the east one; both arrows point at the corridor opening (south of the sign for the viewer)
    dict(kind="strip", at=(-13.4, 2.9), yaw=0.0, entries=[("T131~T150", "S")], z=1.5),
    dict(kind="strip", at=(0.0, 2.9), yaw=math.pi, entries=[("T101~T126", "S")], z=1.5),
]
# --signs real: only the five signs the building actually has (user photos 2026-11-11): the two lobby strips above and three
# strips in the east vertical corridor (red marks 1-3 on the evacuation plan).  1 and 2 are seen looking east, 3 looking west;
# every arrow points along the first leg only (1: "<- T112~T126" at the toilet recess = north up the vertical corridor;
# 2: "^ T112~T121" at the inner corridor opening = straight on, east; 3: "T122~T126 ->" beside the ROEN door = north, then west)
SIGNS_REAL = SIGNS[-2:] + [
    dict(kind="strip", at=(44.4, 5.0), yaw=math.pi, entries=[("T112~T126", "N")], z=1.6),
    dict(kind="strip", at=(44.4, 12.2), yaw=math.pi, entries=[("T112~T121", "E")], z=1.6),
    dict(kind="strip", at=(42.0, 13.5), yaw=0.0, entries=[("T122~T126", "N")], z=1.6),
]
# --c1: two changes for the A1 (C1) runs, world name + '_c1'.  (a) Sign 1 moved out of the vertical corridor, where it hung 1.7 m
# before the T110 plate and its arrow ran along the corridor (no mouth -> never negative evidence, A1 r1 2026-11-13), to the south
# wall of the main corridor 1-3 m before the junction, arrow straight on (east): the robot reads it before it can see T110 / T111.
# (b) Room plates on the door leaf, as in the real building (user 2026-11-13: the number is on the door, not beside it).
# (c) the east wing (x > 9 m, y > 4 m) moved C1_STRETCH m north: the vertical corridor runs that much longer before T110, so a robot
# that reads sign 1 at the junction (strips read from 1-2 m only) does not see T110 / T111 right after it (A1 r2 first run: found
# T110 18 s after reading the sign)
C1_STRETCH = 10.0
SIGN1_MAIN = dict(kind="strip", at=(41.5, 0.0), yaw=math.pi / 2, entries=[("T112~T126", "E")], z=1.6)
DIRS = {"E": 0.0, "NE": math.pi / 4, "N": math.pi / 2, "NW": 3 * math.pi / 4, "W": math.pi, "SW": -3 * math.pi / 4,
        "S": -math.pi / 2, "SE": -math.pi / 4}

# wall props: (x, y on the wall line, wall, kind)
PROPS = [(-41.0, CW, "N", "hydrant"), (-17.6, CW, "N", "hydrant"), (11.0, CW, "N", "hydrant"), (24.0, 19.6, "S", "hydrant"),
         (58.0, 19.6, "S", "hydrant"), (-29.0, 0.0, "S", "extinguisher"), (-19.0, CW, "N", "extinguisher"),
         (14.0, CW, "N", "extinguisher"), (31.0, CW, "N", "extinguisher"), (60.0, 14.6, "N", "extinguisher"),
         (52.5, 19.6, "S", "extinguisher"), (-43.0, CW, "N", "board"), (20.0, CW, "N", "board"), (36.0, CW, "N", "board"),
         (63.6, 12.6, "S", "board")]

# --variant clutter: lobby distractors like the real building (posters, a directory board, X-banners, door-like panels without a
# plate, pillars, benches, an information desk) -- the real lobby produced dozens of false doors / signs the clean world did not
CLUTTER_DOORS = [(-2.5, "W", -13.4), (-5.0, "W", -13.4), (4.6, "W", -13.4), (-3.0, "E", 0.0), (4.6, "E", 0.0),
                 (-8.5, "S", -6.5), (-11.5, "S", -6.5)]
CLUTTER_POSTERS = [  # (s along the wall, wall, coord, lines, background, foreground)
    (-3.75, "W", -13.4, ["KAIST 문지캠퍼스", "진리관", "JINRI HALL  1F"], (20, 50, 110), (255, 255, 255)),
    (-1.2, "E", 0.0, ["2026 가을 학술 세미나", "10.28 (화) 14:00", "장소: T122 대강의실"], (240, 236, 220), (30, 30, 40)),
    (-4.8, "E", 0.0, ["금연 구역", "NO SMOKING", "과태료 100,000원"], (250, 250, 250), (200, 20, 20)),
    (-10.0, "S", -6.5, ["AI 로봇 연구실", "학생 모집", "문의 042-350-7114"], (255, 210, 60), (30, 30, 30)),
    (-2.75, "S", -6.5, ["층별 안내", "1F 강의실 · 연구실", "2F 행정실", "3F 세미나실"], (60, 60, 64), (255, 255, 255)),
    (3.6, "W", -13.4, ["분리수거 안내", "캔 · 플라스틱 · 종이"], (40, 140, 80), (255, 255, 255)),
]
CLUTTER_BANNERS = [  # free-standing X-banners: (x, y, facing yaw, lines, background, foreground)
    (-10.6, -2.4, 0.0, ["CAREER FAIR", "채용 박람회", "2026.11.05~11.06"], (200, 40, 60), (255, 255, 255)),
    (-2.6, 4.0, math.pi, ["WELCOME", "신입생", "오리엔테이션", "10:00 강당"], (30, 110, 170), (255, 255, 255)),
]
CLUTTER_BOXES = [  # (x, y, sx, sy, sz, material) pillars, benches, the information desk
    (-10.2, 4.3, 0.6, 0.6, 2.7, "pillar"), (-3.2, 4.3, 0.6, 0.6, 2.7, "pillar"),
    (-6.7, -5.6, 1.8, 0.45, 0.45, "bench"), (-12.9, -1.0, 0.45, 1.4, 0.45, "bench"), (-3.0, -2.6, 1.6, 0.7, 1.0, "desk"),
]

SPAWN = (-6.7, -1.0, 0.0)   # central lobby between T132 and T101, facing east (yaw 0 keeps the map frame = world - spawn)


# ------------------------------------------------------------------ mesh writer
class Mesh:
    def __init__(self):
        self.v, self.vt, self.f, self.mats = [], [], {}, []

    def quad(self, mat, p, uv):
        """p: 4 corners counter-clockwise seen from the visible side; uv: 4 (u, v)"""
        i = len(self.v)
        self.v += [tuple(map(float, q)) for q in p]
        j = len(self.vt)
        self.vt += [tuple(map(float, q)) for q in uv]
        self.f.setdefault(mat, []).append([(i + k, j + k) for k in range(4)])

    def box(self, mat, c, size, yaw=0.0, uv_front=None, uv_scale=None):
        """axis box (centre, size (sx, sy, sz)) rotated by yaw about z; +x face gets uv_front (atlas rect) when given"""
        sx, sy, sz = (s / 2 for s in size)
        cy_, sy_ = math.cos(yaw), math.sin(yaw)
        R2 = lambda x, y: (c[0] + cy_ * x - sy_ * y, c[1] + sy_ * x + cy_ * y)  # noqa: E731
        corner = lambda x, y, z: (*R2(x, y), c[2] + z)                          # noqa: E731
        faces = {  # name: corners CCW from outside
            "+x": [(sx, -sy, -sz), (sx, sy, -sz), (sx, sy, sz), (sx, -sy, sz)],
            "-x": [(-sx, sy, -sz), (-sx, -sy, -sz), (-sx, -sy, sz), (-sx, sy, sz)],
            "+y": [(sx, sy, -sz), (-sx, sy, -sz), (-sx, sy, sz), (sx, sy, sz)],
            "-y": [(-sx, -sy, -sz), (sx, -sy, -sz), (sx, -sy, sz), (-sx, -sy, sz)],
            "+z": [(-sx, -sy, sz), (sx, -sy, sz), (sx, sy, sz), (-sx, sy, sz)],
            "-z": [(-sx, sy, -sz), (sx, sy, -sz), (sx, -sy, -sz), (-sx, -sy, -sz)]}
        for name, cs in faces.items():
            if name == "+x" and uv_front is not None:
                m, (u0, v0, u1, v1) = uv_front
                self.quad(m, [corner(*q) for q in cs], [(u0, v0), (u1, v0), (u1, v1), (u0, v1)])
            else:
                self.quad(mat, [corner(*q) for q in cs], [(0, 0), (1, 0), (1, 1), (0, 1)])

    def write(self, path, mtl=None, uv=True):
        with open(path, "w") as fo:
            fo.write("# generated by make_jinri.py\n")
            if mtl:
                fo.write("mtllib %s\n" % mtl)
            for p in self.v:
                fo.write("v %.4f %.4f %.4f\n" % p)
            if uv:
                for t in self.vt:
                    fo.write("vt %.5f %.5f\n" % t)
            for m, fs in self.f.items():
                if mtl:
                    fo.write("o %s\nusemtl %s\n" % (m, m))
                for f in fs:
                    for tri in ((f[0], f[1], f[2]), (f[0], f[2], f[3])):
                        if uv:
                            fo.write("f %s\n" % " ".join("%d/%d" % (a + 1, b + 1) for a, b in tri))
                        else:
                            fo.write("f %s\n" % " ".join("%d" % (a + 1) for a, _ in tri))


# ------------------------------------------------------------------ textures
def font(path, size):
    return ImageFont.truetype(path, size)


def tex_wall(path):
    rng = np.random.default_rng(1)
    h, w = 540, 400   # 2.7 m x 2 m at 200 px/m
    img = np.full((h, w, 3), (226, 222, 212), np.float32) + rng.normal(0, 2.5, (h, w, 1))
    img[-24:] = (88, 84, 80)                      # baseboard 12 cm
    img[-26:-24] = (60, 58, 56)
    img[: 12] = (238, 236, 232)                   # ceiling trim
    Image.fromarray(np.clip(img, 0, 255).astype(np.uint8)).save(path)


def tex_floor(path):
    rng = np.random.default_rng(2)
    n = 512                                       # 2 x 2 tiles of 0.6 m -> 1.2 m per texture
    img = np.full((n, n, 3), (196, 188, 172), np.float32) + rng.normal(0, 4, (n, n, 1))
    for k in range(0, n, n // 2):
        img[k:k + 3] = (150, 144, 132)
        img[:, k:k + 3] = (150, 144, 132)
    img[: n // 2, n // 2:] += 8
    img[n // 2:, : n // 2] += 8
    Image.fromarray(np.clip(img, 0, 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(0.6)).save(path)


def tex_ceiling(path):
    n = 256
    img = np.full((n, n, 3), 236, np.uint8)
    img[:3] = img[:, :3] = 200
    img[100:156, 30:226] = 252                    # light panel
    Image.fromarray(img).save(path)


def tex_door(path, kind):
    w, h = 380, 840                               # 0.95 x 2.1 m at 400 px/m
    if kind in ("elevator",):
        img = Image.new("RGB", (w, h), (170, 174, 178))
        d = ImageDraw.Draw(img)
        for x in range(0, w, 7):
            d.line([(x, 0), (x, h)], fill=(160 + (x % 3) * 5, 164, 168))
        d.line([(w // 2, 0), (w // 2, h)], fill=(90, 90, 92), width=4)
        img.save(path)
        return
    base = {"wood": (128, 88, 58), "toilet": (150, 120, 92), "stair": (120, 124, 128), "exit": (110, 118, 124), "plain": (140, 110, 84)}[kind]
    rng = np.random.default_rng(hash(kind) % 1000)
    a = np.full((h, w, 3), base, np.float32)
    a += (rng.normal(0, 6, (h, w // 4)).repeat(4, axis=1)[:, :w, None] * (0.6 if kind in ("wood", "plain", "toilet") else 0.15))
    img = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(1.0))
    d = ImageDraw.Draw(img)
    if kind in ("wood", "plain"):
        d.rectangle([250, 140, 300, 470], fill=(46, 56, 62), outline=(30, 30, 30), width=3)   # vision slit
    if kind == "exit":
        d.rectangle([60, 120, w - 60, 420], fill=(60, 72, 80), outline=(40, 40, 40), width=4)
    d.rectangle([0, h - 60, w, h], fill=tuple(int(c * 0.7) for c in base))                   # kick plate
    img.save(path)


def text_fit(d, txt, fnt_path, box_w, box_h):
    s = int(box_h)
    while s > 6:
        f = font(fnt_path, s)
        l, t, r, b = d.textbbox((0, 0), txt, font=f)
        if r - l <= box_w and b - t <= box_h:
            return f, (l, t, r, b)
        s -= 2
    return font(fnt_path, 6), d.textbbox((0, 0), txt, font=font(fnt_path, 6))


def draw_arrow(d, cx, cy, size, ang, fill):
    """arrow of length `size` centred at (cx, cy), pointing at image angle ang (0 = right, +pi/2 = up)"""
    ux, uy = math.cos(ang), -math.sin(ang)
    px, py = -uy, ux
    L, hw, sw = size / 2, size * 0.32, size * 0.11
    tip = (cx + ux * L, cy + uy * L)
    base = (cx + ux * (L - size * 0.42), cy + uy * (L - size * 0.42))
    tail = (cx - ux * L, cy - uy * L)
    d.polygon([tip, (base[0] + px * hw, base[1] + py * hw), (base[0] + px * sw, base[1] + py * sw),
               (tail[0] + px * sw, tail[1] + py * sw), (tail[0] - px * sw, tail[1] - py * sw),
               (base[0] - px * sw, base[1] - py * sw), (base[0] - px * hw, base[1] - py * hw)], fill=fill)


def view_arrow(world_dir, normal_yaw):
    """image angle of the arrow for a viewer looking at a sign whose face normal is normal_yaw (viewer looks along -normal)"""
    look = normal_yaw + math.pi
    rel = math.atan2(math.sin(DIRS[world_dir] - look), math.cos(DIRS[world_dir] - look))   # + = to the viewer's left
    rel = round(rel / (math.pi / 4)) * (math.pi / 4)
    return math.pi / 2 + rel          # straight ahead = arrow up; left = arrow pointing left


class Atlas:
    def __init__(self, n=4096):
        self.img = Image.new("RGB", (n, n), (255, 255, 255))
        self.n, self.x, self.y, self.rowh = n, 0, 0, 0

    def add(self, im):
        im = im.resize((max(1, im.size[0] // 2), max(1, im.size[1] // 2)), Image.LANCZOS)   # 2000 -> 1000 px per metre
        w, h = im.size
        if self.x + w > self.n:
            self.x, self.y, self.rowh = 0, self.y + self.rowh + 2, 0
        assert self.y + h <= self.n, "atlas full"
        self.img.paste(im, (self.x, self.y))
        r = (self.x / self.n, 1 - (self.y + h) / self.n, (self.x + w) / self.n, 1 - self.y / self.n)
        self.x += w + 2
        self.rowh = max(self.rowh, h)
        return r


def plate_image(num, kind):
    w, h = 600, 280            # 0.30 x 0.14 m
    im = Image.new("RGB", (w, h), (246, 246, 242))
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, w - 1, h - 1], outline=(40, 60, 110), width=10)
    d.rectangle([0, 0, 46, h], fill=(40, 60, 110))
    f, (l, t, r, b) = text_fit(d, num, FONT_B, w - 110, 100)   # 2/3 of the jinri_1f text height (real plates read poorly)
    d.text((70 + (w - 90 - (r - l)) / 2 - l, 47 - t), num, font=f, fill=(20, 24, 30))
    if kind:
        f2, (l2, t2, r2, b2) = text_fit(d, kind, FONT_KR, w - 140, 41)
        d.text((70 + (w - 90 - (r2 - l2)) / 2 - l2, 203 - t2), kind, font=f2, fill=(60, 60, 70))
    return im


def pict_plate(kind):
    w, h = 400, 400            # 0.2 x 0.2 m pictogram plate
    col = {"toilet_m": (40, 90, 170), "toilet_w": (190, 50, 60), "elevator": (90, 90, 96), "stair": (40, 130, 70), "exit": (20, 140, 70)}[kind]
    im = Image.new("RGB", (w, h), col)
    d = ImageDraw.Draw(im)
    d.ellipse([170, 50, 230, 110], fill=(255, 255, 255))
    if kind == "toilet_w":
        d.polygon([(200, 120), (130, 300), (270, 300)], fill=(255, 255, 255))
    else:
        d.rectangle([160, 120, 240, 280], fill=(255, 255, 255))
    lab = {"toilet_m": "남자화장실", "toilet_w": "여자화장실", "elevator": "승강기", "stair": "계단", "exit": "비상구"}[kind]
    f, (l, t, r, b) = text_fit(d, lab, FONT_KR, 360, 60)
    d.text(((w - (r - l)) / 2 - l, 320 - t), lab, font=f, fill=(255, 255, 255))
    return im


def sign_image(entries, normal_yaw, strip=False):
    """multi-line directional sign: dark green panel, white arrows + range text"""
    if strip:
        w, h = 800, 200        # 0.40 x 0.10 m
    else:
        w, h = 1800, LINE_PX * len(entries) + 80   # 0.90 m wide, 11 cm per line
    im = Image.new("RGB", (w, h), (24, 70, 56))
    d = ImageDraw.Draw(im)
    d.rectangle([4, 4, w - 5, h - 5], outline=(230, 230, 230), width=6)
    lh = (h - (40 if strip else 80)) / len(entries)
    for i, (txt, wd) in enumerate(entries):
        y0 = (20 if strip else 40) + i * lh
        ang = view_arrow(wd, normal_yaw)
        left = math.cos(ang) < -0.3                # arrows pointing left go first, others after the text (as on real signs)
        a_sz = lh * 0.8
        f, (l, t, r, b) = text_fit(d, txt, FONT_B, w - a_sz - 120, lh * 0.72)
        if left:
            draw_arrow(d, 40 + a_sz / 2, y0 + lh / 2, a_sz, ang, (255, 255, 255))
            d.text((80 + a_sz - l, y0 + (lh - (b - t)) / 2 - t), txt, font=f, fill=(255, 255, 255))
        else:
            d.text((40 - l, y0 + (lh - (b - t)) / 2 - t), txt, font=f, fill=(255, 255, 255))
            draw_arrow(d, w - 40 - a_sz / 2, y0 + lh / 2, a_sz, ang, (255, 255, 255))
    return im, (w / 2000.0, h / 2000.0)            # 2000 px per metre


def board_image():
    rng = np.random.default_rng(5)
    w, h = 900, 600
    im = Image.new("RGB", (w, h), (176, 140, 96))
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, w - 1, h - 1], outline=(90, 70, 50), width=16)
    for _ in range(9):
        x, y = rng.integers(30, w - 230), rng.integers(30, h - 230)
        c = tuple(int(v) for v in rng.integers(180, 255, 3))
        d.rectangle([x, y, x + rng.integers(120, 220), y + rng.integers(150, 220)], fill=c)
        for k in range(5):
            d.line([(x + 12, y + 20 + 22 * k), (x + 100, y + 20 + 22 * k)], fill=(80, 80, 80), width=4)
    return im


def poster_image(lines, bg, fg, w=600, h=850):
    """0.6 x 0.85 m poster with a few lines of large text (1000 px/m: half the plate resolution, the atlas is nearly full)"""
    im = Image.new("RGB", (w, h), bg)
    d = ImageDraw.Draw(im)
    d.rectangle([7, 7, w - 8, h - 8], outline=fg, width=5)
    lh = (h - 100) / len(lines)
    for i, txt in enumerate(lines):
        f, (l, t, r, b) = text_fit(d, txt, FONT_KR, w - 80, lh * (0.62 if i == 0 else 0.45))
        d.text(((w - (r - l)) / 2 - l, 50 + i * lh + (lh - (b - t)) / 2 - t), txt, font=f, fill=fg)
    return im


def hydrant_image():
    im = Image.new("RGB", (300, 400), (200, 32, 30))
    d = ImageDraw.Draw(im)
    d.rectangle([20, 20, 280, 380], outline=(240, 240, 240), width=8)
    d.rectangle([40, 60, 260, 200], fill=(230, 230, 230))
    f, (l, t, r, b) = text_fit(d, "소화전", FONT_KR, 200, 90)
    d.text((150 - (r - l) / 2 - l, 130 - (b - t) / 2 - t), "소화전", font=f, fill=(200, 30, 30))
    return im


# ------------------------------------------------------------------ build
def wall_frame(wall, coord, s):
    """point on the wall face for position s along it, face normal yaw (into the free space) and the along-wall unit"""
    if wall == "S":      # door in the wall at y = coord, rooms south of it, corridor north -> normal +y
        return (s, coord), math.pi / 2
    if wall == "N":
        return (s, coord), -math.pi / 2
    if wall == "E":      # wall at x = coord, room east, corridor west -> normal -x
        return (coord, s), math.pi
    if wall == "W":
        return (coord, s), 0.0
    raise ValueError(wall)


def stretch_east(k):
    """move everything east of x = 9 m and north of y = 4 m k metres north (the vertical corridor grows by k)"""
    global SIGNS
    sy = lambda x, y: y + k if x > 9.0 and y > 4.0 else y   # noqa: E731
    for i, (x0, x1, y0, y1) in enumerate(FREE):
        FREE[i] = (x0, x1, sy(x0, y0), sy(x0, y1))
    for rm in R:
        if rm["wall"] in ("E", "W"):
            rm["a"], rm["b"] = sy(rm["coord"], rm["a"]), sy(rm["coord"], rm["b"])
        else:
            rm["coord"] = sy(rm["a"], rm["coord"])
    for i, (s, wall, coord, kind) in enumerate(EXTRA_DOORS):
        EXTRA_DOORS[i] = (sy(coord, s), wall, coord, kind) if wall in ("E", "W") else (s, wall, sy(s, coord), kind)
    SIGNS = [dict(s, at=(s["at"][0], sy(*s["at"]))) for s in SIGNS]
    for i, (x, y, wall, kind) in enumerate(PROPS):
        PROPS[i] = (x, sy(x, y), wall, kind)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default=os.path.expanduser("~/raisin_ws/scripts/reasonnav_sim/gt/jinri_1f_rooms.json"))
    ap.add_argument("--preview", default="", help="write a top-view PNG of the layout")
    ap.add_argument("--variant", default="", choices=("", "clutter"), help="clutter: lobby distractors -> world jinri_1f_clutter")
    ap.add_argument("--signs", default="", choices=("", "real"), help="real: only the building's five real signs -> world name + '_rs'")
    ap.add_argument("--c1", action="store_true", help="sign 1 in the main corridor + plates on the doors -> world name + '_c1'")
    a = ap.parse_args()
    global OUT
    name = "jinri_1f" + ("_" + a.variant if a.variant else "") + "_sp" + ("_rs" if a.signs == "real" else "") + ("_c1" if a.c1 else "")
    global SIGNS
    if a.signs == "real":
        SIGNS = SIGNS_REAL
    if a.c1:
        SIGNS = [SIGN1_MAIN if s.get("entries") == [("T112~T126", "N")] else s for s in SIGNS]
        stretch_east(C1_STRETCH)
    if True:
        OUT = os.path.join(os.path.dirname(OUT), name)
        if a.gt == ap.get_default("gt"):
            a.gt = a.gt.replace("jinri_1f_rooms.json", name + "_rooms.json")
    tdir = os.path.join(OUT, "textures")
    os.makedirs(tdir, exist_ok=True)
    tex_wall(os.path.join(tdir, "wall.png"))
    tex_floor(os.path.join(tdir, "floor.png"))
    tex_ceiling(os.path.join(tdir, "ceiling.png"))
    for k in ("wood", "toilet", "stair", "exit", "plain", "elevator"):
        tex_door(os.path.join(tdir, "door_%s.png" % k), k)
    atlas = Atlas()

    vis, col = Mesh(), Mesh()
    free = free_space()
    rings = [free.exterior] + list(free.interiors)
    # walls: one quad per boundary edge, facing the free space; collision = 0.2 m slab behind it
    for ring in rings:
        pts = list(ring.coords)
        for (x0, y0), (x1, y1) in zip(pts[:-1], pts[1:]):
            L = math.hypot(x1 - x0, y1 - y0)
            if L < 1e-6:
                continue
            # exterior is CCW (free space on the left), holes CW: free space is on the left of every edge either way
            # (shapely orient(sign=1) makes the exterior CCW and holes CW)
            u0 = (x0 * (x1 - x0) + y0 * (y1 - y0)) / L / 2.0
            u1 = u0 + L / 2.0
            vis.quad("wall", [(x0, y0, 0), (x1, y1, 0), (x1, y1, WALL_H), (x0, y0, WALL_H)][::-1],
                     [(u0, 0), (u1, 0), (u1, 1), (u0, 1)][::-1])
            # back face too, so the walls also render from outside (top views, a camera that clips through a wall)
            vis.quad("wall", [(x0, y0, 0), (x1, y1, 0), (x1, y1, WALL_H), (x0, y0, WALL_H)], [(u0, 0), (u1, 0), (u1, 1), (u0, 1)])
            nx, ny = (y1 - y0) / L, -(x1 - x0) / L        # right normal = into the wall
            col.box("c", ((x0 + x1) / 2 + nx * 0.1, (y0 + y1) / 2 + ny * 0.1, WALL_H / 2), (L + 0.2, 0.2, WALL_H),
                    yaw=math.atan2(y1 - y0, x1 - x0))
    x0, y0, x1, y1 = free.bounds
    x0, y0, x1, y1 = x0 - 1, y0 - 1, x1 + 1, y1 + 1
    vis.quad("floor", [(x0, y0, 0), (x1, y0, 0), (x1, y1, 0), (x0, y1, 0)], [(x0 / 1.2, y0 / 1.2), (x1 / 1.2, y0 / 1.2), (x1 / 1.2, y1 / 1.2), (x0 / 1.2, y1 / 1.2)])
    vis.quad("ceiling", [(x0, y0, CEIL_H), (x0, y1, CEIL_H), (x1, y1, CEIL_H), (x1, y0, CEIL_H)],
             [(x0 / 1.2, y0 / 1.2), (x0 / 1.2, y1 / 1.2), (x1 / 1.2, y1 / 1.2), (x1 / 1.2, y0 / 1.2)])
    vis.quad("floor", [(x0, y0, 0), (x0, y1, 0), (x1, y1, 0), (x1, y0, 0)], [(x0 / 1.2, y0 / 1.2), (x0 / 1.2, y1 / 1.2), (x1 / 1.2, y1 / 1.2), (x1 / 1.2, y0 / 1.2)])
    vis.quad("ceiling", [(x0, y0, CEIL_H), (x1, y0, CEIL_H), (x1, y1, CEIL_H), (x0, y1, CEIL_H)],
             [(x0 / 1.2, y0 / 1.2), (x1 / 1.2, y0 / 1.2), (x1 / 1.2, y1 / 1.2), (x0 / 1.2, y1 / 1.2)])
    col.box("c", ((x0 + x1) / 2, (y0 + y1) / 2, -0.05), (x1 - x0, y1 - y0, 0.1))

    def door(p, nyaw, kind, w=0.95, handle=True):
        """door on a wall face at p (x, y), normal nyaw; returns the along-wall unit vector"""
        tx, ty = -math.sin(nyaw), math.cos(nyaw)          # along the wall (90 deg CCW from the normal)
        nx, ny = math.cos(nyaw), math.sin(nyaw)
        mat = {"wood": "door_wood", "plain": "door_plain", "toilet": "door_toilet", "stair": "door_stair", "exit": "door_exit",
               "elevator": "door_elevator"}[kind]
        # leaf: thin box, its +x face (textured) towards the corridor
        c = (p[0] + nx * 0.015, p[1] + ny * 0.015, 1.05)
        vis.box(mat + "_side", c, (0.03, w, 2.1), yaw=nyaw, uv_front=(mat, (0, 0, 1, 1)))
        col.box("c", c, (0.03, w, 2.1), yaw=nyaw)
        for s in (-1, 1):   # jambs
            cc = (p[0] + nx * 0.025 + tx * s * (w / 2 + 0.03), p[1] + ny * 0.025 + ty * s * (w / 2 + 0.03), 1.08)
            vis.box("frame", cc, (0.05, 0.06, 2.16), yaw=nyaw)
            col.box("c", cc, (0.05, 0.06, 2.16), yaw=nyaw)
        cc = (p[0] + nx * 0.025, p[1] + ny * 0.025, 2.13)
        vis.box("frame", cc, (0.05, w + 0.12, 0.06), yaw=nyaw)
        if kind != "elevator" and handle:
            hx = (p[0] + nx * 0.07 + tx * (w / 2 - 0.12), p[1] + ny * 0.07 + ty * (w / 2 - 0.12), 1.0)
            vis.box("metal", hx, (0.03, 0.14, 0.025), yaw=nyaw)
        return tx, ty, nx, ny

    def plate(p, nyaw, im, size, z):
        r = atlas.add(im)
        c = (p[0] + math.cos(nyaw) * 0.006, p[1] + math.sin(nyaw) * 0.006, z)
        vis.box("plate_edge", c, (0.012, size[0], size[1]), yaw=nyaw, uv_front=("atlas", r))
        return c

    gt = {"note": "room plate centres in the raisim world frame of jinri_1f.xml; the SLAM/map frame is this frame shifted by the "
                  "robot spawn pose (spawn_xy, yaw 0)", "spawn_xy": [SPAWN[0], SPAWN[1]], "spawn_yaw": SPAWN[2], "rooms": {}, "doors": []}
    for rm in R:
        span = rm["b"] - rm["a"]
        offs = {"start": [1.1], "end": [span - 1.1], "mid": [span / 2], "both": [1.1, span - 1.1]}[rm["door_at"]]
        for o in offs:
            s = rm["a"] + o
            p, nyaw = wall_frame(rm["wall"], rm["coord"], s)
            tx, ty, nx, ny = door(p, nyaw, "wood")
            # plate beside the door on the side away from the hinge-handle, centred 1.55 m high
            side = -1 if o > span / 2 else 1
            side = side if rm["door_at"] != "end" else -1
            q = (p[0] + tx * side * 0.80, p[1] + ty * side * 0.80)
            if a.c1:     # on the leaf (its face is 0.03 m out from the wall)
                q = (p[0] + nx * 0.031, p[1] + ny * 0.031)
            c = plate(q, nyaw, plate_image(rm["num"], rm["kind"]), (0.30, 0.14), 1.55)
            key = rm["num"]
            gt["rooms"].setdefault(key, {"xy": [round(c[0], 3), round(c[1], 3)], "z": 1.55, "all_xy": []})
            gt["rooms"][key]["all_xy"].append([round(c[0], 3), round(c[1], 3)])
            gt["doors"].append({"room": key, "xy": [round(p[0], 3), round(p[1], 3)], "normal_yaw": round(nyaw, 4)})

    for s, wall, coord, kind in EXTRA_DOORS:
        p, nyaw = wall_frame(wall, coord, s)
        k = kind.split("_")[0] if kind.startswith("plain") else kind
        dk = {"elevator": "elevator", "toilet_m": "toilet", "toilet_w": "toilet", "stair": "stair", "plain": "plain", "exit": "exit"}[k]
        tx, ty, nx, ny = door(p, nyaw, dk, w=1.6 if dk in ("elevator", "exit") else 0.95)
        gt["doors"].append({"room": None, "kind": kind, "xy": [round(p[0], 3), round(p[1], 3)], "normal_yaw": round(nyaw, 4)})
        if k in ("toilet_m", "toilet_w", "elevator", "stair"):
            plate((p[0] + tx * 0.85, p[1] + ty * 0.85), nyaw, pict_plate(k), (0.2, 0.2), 1.55)
        if k == "exit":   # green running-man sign above the door
            plate((p[0], p[1]), nyaw, pict_plate("exit").resize((400, 200)), (0.36, 0.18), 2.42)

    gt["signs"] = []
    for sg in SIGNS:
        if sg["kind"] == "hang":
            x, y = sg["at"]
            for face, ents in sg["faces"].items():
                nyaw = (0.0 if face == "+" else math.pi) if sg["axis"] == "x" else (math.pi / 2 if face == "+" else -math.pi / 2)
                im, size = sign_image(ents, nyaw)
                r = atlas.add(im)
                c = (x + math.cos(nyaw) * 0.012, y + math.sin(nyaw) * 0.012, 2.12)
                vis.box("sign_back", c, (0.02, size[0], size[1]), yaw=nyaw, uv_front=("atlas", r))
                gt["signs"].append({"xy": [round(c[0], 2), round(c[1], 2)], "z": 2.12, "normal_yaw": round(nyaw, 3), "entries": ents, "kind": "hang"})
            for s in (-1, 1):   # suspension rods
                tx, ty = (0.0, 1.0) if sg["axis"] == "x" else (1.0, 0.0)
                vis.box("metal", (x + tx * s * 0.4, y + ty * s * 0.4, (2.12 + sg_h(sg) / 2 + CEIL_H) / 2), (0.015, 0.015, CEIL_H - 2.12 - sg_h(sg) / 2))
        else:
            strip = sg["kind"] == "strip"
            nyaw = sg["yaw"]
            im, size = sign_image(sg["entries"], nyaw, strip=strip)
            r = atlas.add(im)
            z = sg.get("z", 1.55 if strip else 1.9)
            c = (sg["at"][0] + math.cos(nyaw) * 0.008, sg["at"][1] + math.sin(nyaw) * 0.008, z)
            vis.box("sign_back", c, (0.015, size[0], size[1]), yaw=nyaw, uv_front=("atlas", r))
            gt["signs"].append({"xy": [round(c[0], 2), round(c[1], 2)], "z": z, "normal_yaw": round(nyaw, 3), "entries": sg["entries"], "kind": sg["kind"]})

    hyd_r, board_r = atlas.add(hydrant_image()), atlas.add(board_image())
    for x, y, wall, kind in PROPS:
        p, nyaw = wall_frame(wall, y if wall in ("N", "S") else x, x if wall in ("N", "S") else y)
        nx, ny = math.cos(nyaw), math.sin(nyaw)
        if kind == "hydrant":
            c = (p[0] + nx * 0.09, p[1] + ny * 0.09, 0.95)
            vis.box("red", c, (0.18, 0.75, 1.0), yaw=nyaw, uv_front=("atlas", hyd_r))
            col.box("c", c, (0.18, 0.75, 1.0), yaw=nyaw)
        elif kind == "extinguisher":
            c = (p[0] + nx * 0.12, p[1] + ny * 0.12, 0.28)
            vis.box("red", c, (0.17, 0.17, 0.56), yaw=nyaw)
            col.box("c", c, (0.17, 0.17, 0.56), yaw=nyaw)
        elif kind == "board":
            c = (p[0] + nx * 0.015, p[1] + ny * 0.015, 1.45)
            vis.box("frame", c, (0.03, 1.2, 0.8), yaw=nyaw, uv_front=("atlas", board_r))

    if a.variant == "clutter":
        for s_, wall, coord in CLUTTER_DOORS:          # door-like panels: frame + leaf, no handle, no plate
            p, nyaw = wall_frame(wall, coord, s_)
            door(p, nyaw, "plain", w=1.0, handle=False)
            gt["doors"].append({"room": None, "kind": "panel", "xy": [round(p[0], 3), round(p[1], 3)], "normal_yaw": round(nyaw, 4)})
        gt["distractors"] = []
        for s_, wall, coord, lines, bg, fg in CLUTTER_POSTERS:
            p, nyaw = wall_frame(wall, coord, s_)
            plate(p, nyaw, poster_image(lines, bg, fg), (0.6, 0.85), 1.45)
            gt["distractors"].append({"kind": "poster", "xy": [round(p[0], 2), round(p[1], 2)], "text": " / ".join(lines)})
        for x, y, yaw, lines, bg, fg in CLUTTER_BANNERS:
            r = atlas.add(poster_image(lines, bg, fg, 600, 1600))
            for side in (0.0, math.pi):              # printed on both sides
                vis.box("sign_back", (x + math.cos(yaw + side) * 0.006, y + math.sin(yaw + side) * 0.006, 1.1), (0.012, 0.6, 1.6),
                        yaw=yaw + side, uv_front=("atlas", r))
            col.box("c", (x, y, 1.1), (0.04, 0.6, 1.6), yaw=yaw)
            vis.box("metal", (x, y, 0.15), (0.5, 0.5, 0.02), yaw=yaw)
            gt["distractors"].append({"kind": "banner", "xy": [x, y], "text": " / ".join(lines)})
        for x, y, sx, sy, sz, m in CLUTTER_BOXES:
            vis.box(m, (x, y, sz / 2), (sx, sy, sz))
            col.box("c", (x, y, sz / 2), (sx, sy, sz))
            if m == "desk":
                plate((x, y - sy / 2 - 0.01), -math.pi / 2, poster_image(["안내  INFORMATION"], (30, 30, 34), (255, 255, 255), 1200, 250), (1.2, 0.25), 0.75)

    # ------------------------------------------------------------ write
    atlas.img.save(os.path.join(tdir, "atlas.png"))
    mats = {"wall": ("textures/wall.png", None), "floor": ("textures/floor.png", None), "ceiling": ("textures/ceiling.png", None),
            "atlas": ("textures/atlas.png", None), "frame": (None, (0.42, 0.40, 0.38)), "metal": (None, (0.75, 0.75, 0.78)),
            "plate_edge": (None, (0.85, 0.85, 0.85)), "sign_back": (None, (0.25, 0.27, 0.27)), "red": (None, (0.78, 0.10, 0.10)),
            "pillar": (None, (0.80, 0.78, 0.74)), "bench": (None, (0.30, 0.32, 0.36)), "desk": (None, (0.55, 0.45, 0.35))}
    for k in ("wood", "toilet", "stair", "exit", "plain", "elevator"):
        mats["door_" + k] = ("textures/door_%s.png" % k, None)
        mats["door_%s_side" % k] = (None, (0.35, 0.28, 0.22))
    with open(os.path.join(OUT, "visual.mtl"), "w") as fo:
        for m, (tex, kd) in mats.items():
            fo.write("newmtl %s\nKa 0.2 0.2 0.2\nKd %s\nKs 0.05 0.05 0.05\nNs 10\n" % (m, "1.0 1.0 1.0" if tex else "%.3f %.3f %.3f" % kd))
            if tex:
                fo.write("map_Kd %s\n" % tex)
            fo.write("\n")
    vis.write(os.path.join(OUT, "visual.obj"), "visual.mtl")
    col.write(os.path.join(OUT, "collision.obj"), uv=False)
    write_urdf(os.path.join(OUT, name + ".urdf"))
    write_world(os.path.join(os.path.dirname(OUT), "raisim_config", name + ".xml"), name)
    os.makedirs(os.path.dirname(a.gt), exist_ok=True)
    json.dump(gt, open(a.gt, "w"), indent=1, ensure_ascii=False)
    print("visual: %d verts, %d quads | collision: %d quads | rooms %d, doors %d, signs %d | gt -> %s"
          % (len(vis.v), sum(len(f) for f in vis.f.values()), sum(len(f) for f in col.f.values()), len(gt["rooms"]), len(gt["doors"]),
             len(gt["signs"]), a.gt))
    if a.preview:
        preview(free, gt, a.preview)


def sg_h(sg):
    n = max(len(v) for v in sg["faces"].values())
    return (LINE_PX * n + 80) / 2000.0


def write_urdf(path):
    open(path, "w").write("""<?xml version="1.0"?>
<!-- Generated by tools/make_jinri.py. Fixed-base static environment (KAIST Jinri-gwan 1F). -->
<robot name="jinri_1f">
  <link name="world"/>
  <joint name="world_to_jinri" type="fixed">
    <parent link="world"/>
    <child link="jinri"/>
    <origin xyz="0 0 0" rpy="0 0 0"/>
  </joint>
  <link name="jinri">
    <inertial>
      <mass value="1000"/>
      <inertia ixx="1" ixy="0" ixz="0" iyy="1" iyz="0" izz="1"/>
    </inertial>
    <visual>
      <geometry>
        <mesh filename="visual.obj"/>
      </geometry>
    </visual>
    <collision>
      <geometry>
        <mesh filename="collision.obj"/>
      </geometry>
    </collision>
  </link>
  <!-- raisim segfaults on a 0-DOF articulated system: one massless dummy joint (see ../hospital/README.md) -->
  <joint name="jinri_dummy_joint" type="revolute">
    <parent link="jinri"/>
    <child link="jinri_dummy_link"/>
    <origin xyz="0 0 0" rpy="0 0 0"/>
    <axis xyz="0 0 1"/>
    <dynamics damping="1.0" friction="0.0"/>
  </joint>
  <link name="jinri_dummy_link">
    <inertial>
      <mass value="0.001"/>
      <inertia ixx="1e-6" ixy="0" ixz="0" iyy="1e-6" iyz="0" izz="1e-6"/>
    </inertial>
  </link>
</robot>
""")


def write_world(path, name="jinri_1f"):
    x, y, yaw = SPAWN
    q = "%.6f, 0.0, 0.0, %.6f" % (math.cos(yaw / 2), math.sin(yaw / 2))
    open(path, "w").write("""<?xml version="1.0" ?>
<!-- KAIST Munji campus Jinri-gwan 1F (rooms T101-T146), generated by ../jinri_1f/tools/make_jinri.py from the evacuation plan.
     The floor slab (collision.obj) is at z = 0; the raisim ground 5 cm below is a safety net only. -->
<raisim version="1.0">
    <gravity value="0.000000, 0.000000, -9.810000" />
    <timeStep value="0.001" />
    <objects>
        <ground name="terrain" height="-0.05" collisionGroup="-2147483648" collisionMask="-1">
            <dim height="-0.05" />
            <state />
        </ground>
        <articulatedSystem name="jinri_1f" resDir="[THIS_DIR]/../%s" urdfPath="[THIS_DIR]/../%s/%s.urdf" collisionGroup="-2147483648" collisionMask="-1">
            <state qpos="0" qvel="0" />
        </articulatedSystem>
        <!-- Robot spawns at the plan's "you are here" mark (between T105 and T106). -->
        <articulatedSystem name="robot" resDir="[THIS_DIR]/.." urdfPath="[THIS_DIR]/../urdf/@@URDF" collisionGroup="1" collisionMask="-1" modules="@@MODULES">
            <state qpos="%.3f, %.3f, 0.0675, %s, 0, 2.5, -2.64, 0, 2.5, -2.64, 0, 2.5, -2.64, 0, 2.5, -2.64" qvel="0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000" />
        </articulatedSystem>
    </objects>
</raisim>
""" % (name, name, name, x, y, q))


def preview(free, gt, path):
    s = 10.0
    x0, y0, x1, y1 = free.bounds
    W, H = int((x1 - x0 + 4) * s), int((y1 - y0 + 4) * s)
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    P = lambda x, y: ((x - x0 + 2) * s, (y1 + 2 - y) * s)   # noqa: E731
    for ring in [free.exterior] + list(free.interiors):
        d.line([P(*q) for q in ring.coords], fill=(0, 0, 0), width=2)
    f = font(FONT_B, 11)
    for k, v in gt["rooms"].items():
        for xy in v["all_xy"]:
            d.ellipse([P(*xy)[0] - 3, P(*xy)[1] - 3, P(*xy)[0] + 3, P(*xy)[1] + 3], fill=(200, 0, 200))
        d.text(P(*v["xy"]), k, font=f, fill=(120, 0, 120))
    for dd in gt["doors"]:
        if dd["room"] is None:
            d.rectangle([P(*dd["xy"])[0] - 3, P(*dd["xy"])[1] - 3, P(*dd["xy"])[0] + 3, P(*dd["xy"])[1] + 3], fill=(0, 150, 0))
    for sg in gt["signs"]:
        d.rectangle([P(*sg["xy"])[0] - 4, P(*sg["xy"])[1] - 4, P(*sg["xy"])[0] + 4, P(*sg["xy"])[1] + 4], fill=(0, 120, 255))
    sx, sy = P(SPAWN[0], SPAWN[1])
    d.ellipse([sx - 6, sy - 6, sx + 6, sy + 6], fill=(255, 0, 0))
    im.save(path)


if __name__ == "__main__":
    main()
