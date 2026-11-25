"""Confidence grid in the style of 'Follow the Signs: Using Textual Cues and LLMs to Guide Efficient Robot Navigation'
(Cao, Kumar, Curtis).

An LLM is shown the room numbers read so far (with positions) and predicts where the goal room is relative to the robot.
Each prediction adds +1 to the cells in that direction, all older evidence decays by alpha, and cells the robot has already
looked at (and that did not contain the goal) are reset to 0. Candidates in high-confidence areas are favoured; with no
evidence (all zeros) the finder falls back to plain frontier exploration.

Differences from the paper: eight directions (45 degree wedges) instead of four half-planes, because the building wraps around.
"""
import math

import cv2
import numpy as np

DIRS = ("east", "north-east", "north", "north-west", "west", "south-west", "south", "south-east")
ANG = {d: i * math.pi / 4 for i, d in enumerate(DIRS)}


class BeliefGrid:
    def __init__(self, shape, x0, y0, res, alpha=0.85, look_radius=3.0):
        self.shape, self.x0, self.y0, self.res = shape, x0, y0, res
        self.alpha, self.look_r = alpha, look_radius
        self.C = np.zeros(shape, np.float32)
        self.looked = np.zeros(shape, np.uint8)
        self.S = np.zeros(shape, np.float32)      # static layer from directional signs (not decayed; erased where the robot has looked)
        self.X = np.ones(shape, np.float32)       # multiplicative exclusion from signs whose arrow points away from the goal
        self._sign_sig = None
        self.updates = 0
        h, w = shape
        self._yy, self._xx = np.mgrid[0:h, 0:w]

    def migrate(self, shape, x0, y0):
        """the finder map is cropped to the known area and its origin / size change as the robot explores: carry the confidence, the looked-at cells
        and the sign layers over into the new grid (same resolution) instead of starting from zero"""
        new = BeliefGrid(shape, x0, y0, self.res, alpha=self.alpha, look_radius=self.look_r)
        dc, dr = int(round((self.x0 - x0) / self.res)), int(round((self.y0 - y0) / self.res))
        h, w = self.shape
        H, W = shape
        r0, c0, r1, c1 = max(0, dr), max(0, dc), min(H, dr + h), min(W, dc + w)
        if r1 > r0 and c1 > c0:
            for name in ("C", "looked", "S", "X"):
                getattr(new, name)[r0:r1, c0:c1] = getattr(self, name)[r0 - dr:r1 - dr, c0 - dc:c1 - dc]
        new._sign_sig, new.updates = self._sign_sig, self.updates
        return new

    def matches(self, shape, x0, y0, res):
        return shape == self.shape and abs(x0 - self.x0) < 1e-6 and abs(y0 - self.y0) < 1e-6 and abs(res - self.res) < 1e-9

    def cell(self, x, y):
        return int((y - self.y0) / self.res), int((x - self.x0) / self.res)

    def look(self, x, y, occ=None, open_mask=None, far=0.0):
        """the robot saw everything within look_r of (x, y): those cells cannot hide the goal any more. The circle goes through walls:
        the wall cells (plates) and what is right behind them count only after a close pass.
        far > look_r with occ (bool grid of this shape, True = obstacle) and open_mask (True = open space, e.g. >= 1 m from obstacles):
        also the open cells in line of sight within far (rays stop at the first obstacle cell; the first 0.4 m is skipped, the robot
        may stand in a wall's inflation)"""
        r, c = self.cell(x, y)
        cv2.circle(self.looked, (c, r), int(self.look_r / self.res), 1, -1)
        n = int(far / self.res)
        if far > self.look_r and occ is not None and occ.shape == self.looked.shape:
            ang = np.linspace(-np.pi, np.pi, max(64, int(2 * np.pi * n)), endpoint=False)
            steps = np.arange(n + 1)
            rr = np.rint(r + np.outer(np.sin(ang), steps)).astype(int)
            cc = np.rint(c + np.outer(np.cos(ang), steps)).astype(int)
            ok = (rr >= 0) & (rr < occ.shape[0]) & (cc >= 0) & (cc < occ.shape[1])
            hit = np.zeros(ok.shape, bool)
            hit[ok] = occ[rr[ok], cc[ok]]
            hit[:, : int(0.4 / self.res)] = False
            vis = ok & (np.cumsum(hit, axis=1) == 0)
            if open_mask is not None and open_mask.shape == self.looked.shape:
                vis[vis] = open_mask[rr[vis], cc[vis]]
            self.looked[rr[vis], cc[vis]] = 1
        self.C[self.looked > 0] = 0.0

    def set_exclusions(self, circles, factor=0.2):
        """areas the VLM says cannot hold the goal (e.g. a hallway of another number range): confidence there is multiplied by `factor`; rebuilt on every answer"""
        self.X[:] = 1.0
        for cx, cy, r in circles:
            wx = self.x0 + (self._xx + 0.5) * self.res - cx
            wy = self.y0 + (self._yy + 0.5) * self.res - cy
            m = np.hypot(wx, wy) <= r
            self.X[m] = np.minimum(self.X[m], factor)

    def add_point(self, gx, gy, sigma=6.0, decay=True, weight=1.0):
        """the VLM named a map position for the goal: older evidence decays, then a gaussian blob (sigma m) is added there (not on looked cells)"""
        if decay:
            self.C *= self.alpha
        wx = self.x0 + (self._xx + 0.5) * self.res - gx
        wy = self.y0 + (self._yy + 0.5) * self.res - gy
        blob = np.exp(-(wx * wx + wy * wy) / (2.0 * sigma * sigma)).astype(np.float32)
        self.C[self.looked == 0] += weight * blob[self.looked == 0]
        self.updates += 1
        return True

    def add_prediction(self, region, x, y, wedge=math.pi / 2, range_m=0.0):
        """+1 for every cell inside the wedge pointing to `region` from (x, y); older evidence decays first"""
        if region not in ANG:
            return False
        self.C *= self.alpha
        wx = self.x0 + (self._xx + 0.5) * self.res - x
        wy = self.y0 + (self._yy + 0.5) * self.res - y
        diff = np.abs((np.arctan2(wy, wx) - ANG[region] + math.pi) % (2 * math.pi) - math.pi)
        inc = (diff <= wedge / 2) & (self.looked == 0)
        if range_m > 0:        # nearer cells in that direction count more: the goal is usually not at the far end of the building
            self.C[inc] += np.exp(-np.hypot(wx, wy)[inc] / range_m).astype(np.float32)
        else:
            self.C[inc] += 1.0
        self.updates += 1
        return True

    def set_signs(self, wedges, sig):
        """wedges: [(x, y, bearing, weight, half_angle, length_m)]; rebuilt only when `sig` changes"""
        if sig == self._sign_sig:
            return
        self._sign_sig = sig
        self.S[:] = 0.0
        for x, y, br, w, half, length in wedges:
            wx = self.x0 + (self._xx + 0.5) * self.res - x
            wy = self.y0 + (self._yy + 0.5) * self.res - y
            diff = np.abs((np.arctan2(wy, wx) - br + math.pi) % (2 * math.pi) - math.pi)
            self.S[(diff <= half) & (np.hypot(wx, wy) <= length) & (np.hypot(wx, wy) >= 1.0)] += w

    def set_steer(self, pos, neg, sig):
        """pos: [(x, y, bearing, weight, half_angle, length_m)] added to the sign layer (entry lists the goal in that direction);
        neg: same tuples with a factor in (0,1) the confidence is multiplied by (entry that does not contain the goal)"""
        if sig == self._sign_sig:
            return
        self._sign_sig = sig
        self.S[:] = 0.0
        self.X[:] = 1.0
        for kind, wedges in (("pos", pos), ("neg", neg)):
            for x, y, br, w, half, length in wedges:
                wx = self.x0 + (self._xx + 0.5) * self.res - x
                wy = self.y0 + (self._yy + 0.5) * self.res - y
                diff = np.abs((np.arctan2(wy, wx) - br + math.pi) % (2 * math.pi) - math.pi)
                m = (diff <= half) & (np.hypot(wx, wy) <= length) & (np.hypot(wx, wy) >= 1.0)
                if kind == "pos":
                    self.S[m] += w
                else:
                    self.X[m] = np.minimum(self.X[m], w)

    def combined(self):
        return np.clip(self.C + np.where(self.looked > 0, 0.0, self.S), 0.0, None) * self.X

    def score(self, x, y, radius=3.0):
        """0..1: mean confidence around (x, y), relative to the current maximum (LLM evidence C plus the sign layer S)"""
        Z = self.combined()
        mx = float(Z.max())
        if mx <= 1e-6:
            return 0.0
        r, c = self.cell(x, y)
        n = int(radius / self.res)
        r0, r1, c0, c1 = max(0, r - n), min(self.shape[0], r + n + 1), max(0, c - n), min(self.shape[1], c + n + 1)
        if r0 >= r1 or c0 >= c1:
            return 0.0
        return float(Z[r0:r1, c0:c1].mean()) / mx

    def as_occupancy(self):
        """int8 0..100 for display"""
        Z = self.combined()
        mx = float(Z.max())
        return (np.clip(Z / mx, 0, 1) * 100).astype(np.int8) if mx > 1e-6 else np.zeros(self.shape, np.int8)
