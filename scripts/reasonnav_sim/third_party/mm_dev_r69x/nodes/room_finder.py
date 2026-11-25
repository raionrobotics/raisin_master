#!/usr/bin/env python3
"""Room finder: drive the raibo to a given room number using door plates and navigational signs.

Inputs : /global_costmap/costmap (lidar map with unknown space, from the glue), /room_finder/registry (perception),
         TF map -> base_link.
Output : /room_finder/goal  (carrot 2-3 m ahead on our own A* path; the glue turns it into a raisin waypoint),
         /room_finder/status, /room_finder/markers, result.json in the run directory.

Policy
  1. the target's plate has been read      -> go to its door and stop next to it (SUCCESS once within `arrive_dist`)
  2. a sign whose cues were not read yet    -> go to a viewpoint in front of it (paper: view the sign head-on)
  3. a sign cue whose range holds the target gives a bearing from the sign; plates read so far give a predicted
     position by linear interpolation of the room numbers.  Frontiers and unread doors are ranked by path cost plus
     distance to that hint, so the robot heads where the target should be and reads doors on the way.
"""
import base64
import json
import math
import os
import sys
import time
import zlib

import cv2
import numpy as np
import rclpy
from geometry_msgs.msg import Point, PoseStamped
from nav_msgs.msg import OccupancyGrid
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from scipy.ndimage import distance_transform_edt
from skimage.graph import MCP_Geometric
from std_msgs.msg import ColorRGBA, String
from tf2_ros import Buffer, TransformListener
from visualization_msgs.msg import Marker, MarkerArray


def wrap(a):
    return (a + math.pi) % (2 * math.pi) - math.pi


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))   # mm_dev.room_finder lives in the source tree, not in the install
from mm_dev.room_finder import roomno  # noqa: E402

def passage_trav(d, res, half_width):
    """Traversable cells of an occupancy grid: known, not an obstacle, and holding a point >= half_width from every obstacle
    hit, i.e. a passage is traversable when it is >= 2 x half_width wide. d: -1 unknown, 0 free, 99 inflated, 100 obstacle,
    101..125 obstacle whose mean hit sits at (lx, ly) * 0.2 cells from the cell centre, lx = (v - 101) % 5 - 2,
    ly = (v - 101) // 5 - 2 (gateway --subcell; 100 = the centre).
    Far from the limit the cell-centre distance decides. Within ~1.5 cells of it: the exact clearance E at the cell centre
    (nearest hit position h) and the best point of the cell in the direction g away from h: at most E + r inside the cell
    (r = half the cell's extent along g) and at most (E + E_q + s) / 2, q the neighbour towards g at distance s (the ridge
    between two centres; E changes by at most the distance moved), so a passage's middle is found whatever the grid offset
    and the wall angle. Only the neighbour away from the nearest hit: along a passage E stays the same and the bound would
    add half a cell. 11-11: on 5 cm cells, centres only, a 1.12 m passage read 1.10 or 1.15 m depending on the offset and a
    1.2 m one stepped to 1.15 m where its wall crossed a cell row; with hit positions they read 1.12 and 1.20 m."""
    hard = d >= 100
    known = (d >= 0) & ~hard
    if not hard.any():
        return known.copy()
    q = half_width / res                                              # cells
    dc = cv2.distanceTransform((~hard).astype(np.uint8), cv2.DIST_L2, cv2.DIST_MASK_PRECISE)   # cells, centre to centre (exact)
    trav = known & (dc >= q + 1.2)                                    # a hit is at most 0.57 cells off its cell centre
    band = known & (dc >= q - 1.5) & ~trav
    if not band.any():
        return trav
    from scipy.spatial import cKDTree
    code = np.where(d > 100, d.astype(np.int16) - 101, 12)
    hr, hc = np.nonzero(hard)
    tree = cKDTree(np.column_stack([hc + 0.5 + (code[hr, hc] % 5 - 2) * 0.2, hr + 0.5 + (code[hr, hc] // 5 - 2) * 0.2]))
    br, bc = np.nonzero(band)
    Ep, hi = tree.query(np.column_stack([bc + 0.5, br + 0.5]))
    gx, gy = (bc + 0.5 - tree.data[hi, 0]) / np.maximum(Ep, 1e-9), (br + 0.5 - tree.data[hi, 1]) / np.maximum(Ep, 1e-9)
    m = np.maximum(np.abs(gx), np.abs(gy))
    sx = np.where(np.abs(gx) >= 0.414 * m, np.sign(gx), 0).astype(int)    # the 8-neighbour closest to g
    sy = np.where(np.abs(gy) >= 0.414 * m, np.sign(gy), 0).astype(int)
    Eq = tree.query(np.column_stack([bc + sx + 0.5, br + sy + 0.5]))[0]
    best = np.minimum(Ep + 0.5 * (np.abs(gx) + np.abs(gy)), (Ep + Eq + np.hypot(sx, sy)) / 2)
    trav[br, bc] = np.maximum(best, Ep) >= q - 1e-6
    return trav


class GridMap:
    """Occupancy grid helpers: clearance, cost map, path planning, frontiers."""

    def __init__(self, msg, inflate=0.30, soft=0.9, weight=6.0, occ_clear=0.0, grid_res=0.0):
        res = float(msg.info.resolution)
        h, w = msg.info.height, msg.info.width
        x0, y0 = float(msg.info.origin.position.x), float(msg.info.origin.position.y)
        d = np.array(msg.data, dtype=np.int8).reshape(h, w)
        trav = None
        self.subcell, self.occ_clear_used = bool((d > 100).any()), occ_clear
        if occ_clear > 0:
            # traversable = a passage >= 2 x occ_clear wide (passage_trav), on the map as it comes; the map's inflated band (99)
            # does not count. Without the gateway's hit positions a wall is only known to the cell: 0.575 still lets 1.2 m
            # through on 5 cm cells (1.12 m too when it reads 1.15 m), 0.5 on 10 cm cells
            if not self.subcell:
                occ_clear = min(occ_clear, 0.575 if res <= 0.075 else 0.5)
            self.occ_clear_used = occ_clear
            trav = passage_trav(d, res, occ_clear)
        k = int(round(grid_res / res)) if grid_res > 0 else 1
        if k > 1:
            # a map finer than the finder's grid (the gateway's 5 cm map): k x k blocks on a lattice fixed in map coordinates (the
            # gateway's crop moves by single cells; belief / looked grids migrate by whole cells), the most occupied state of a block
            # wins (obstacle > inflated > free > unknown), a block is traversable when one of its cells is
            pc, pr = int(round(x0 / res)) % k, int(round(y0 / res)) % k
            H, W = -(-(h + pr) // k) * k, -(-(w + pc) // k) * k
            p = np.full((H, W), -1, np.int8)
            p[pr:pr + h, pc:pc + w] = d
            b = p.reshape(H // k, k, W // k, k)
            d = np.full((H // k, W // k), -1, np.int8)
            d[(b == 0).any(axis=(1, 3))] = 0
            d[(b == 99).any(axis=(1, 3))] = 99
            d[(b >= 100).any(axis=(1, 3))] = 100
            if trav is not None:
                t = np.zeros((H, W), bool)
                t[pr:pr + h, pc:pc + w] = trav
                trav = t.reshape(H // k, k, W // k, k).any(axis=(1, 3)) & (d < 100)
            x0, y0, h, w, res = x0 - pc * res, y0 - pr * res, H // k, W // k, res * k
        self.res, self.w, self.h, self.x0, self.y0 = res, w, h, x0, y0
        self.occ, self.free, self.unk = d >= 50, (d >= 0) & (d < 50), d < 0
        # clearance (m) to the nearest obstacle; unknown does not count as an obstacle, but is not traversable
        self.clear = distance_transform_edt(~self.occ) * self.res
        # traversable inflated cells (occ_clear) get the cost of zero clearance
        self.trav = trav if trav is not None else self.free & (self.clear >= inflate)
        cost = np.where(self.trav, 1.0 + np.clip(soft - self.clear, 0.0, None) * weight, np.inf)
        self.cost = cost

    def to_cell(self, x, y):
        return int(math.floor((y - self.y0) / self.res)), int(math.floor((x - self.x0) / self.res))

    def to_xy(self, r, c):
        return self.x0 + (c + 0.5) * self.res, self.y0 + (r + 0.5) * self.res

    def inside(self, r, c):
        return 0 <= r < self.h and 0 <= c < self.w

    def nearest_trav(self, x, y, radius=1.0):
        r, c = self.to_cell(x, y)
        n = int(radius / self.res)
        best = None
        for dr in range(-n, n + 1):
            for dc in range(-n, n + 1):
                rr, cc = r + dr, c + dc
                if self.inside(rr, cc) and self.trav[rr, cc]:
                    dd = dr * dr + dc * dc
                    if best is None or dd < best[0]:
                        best = (dd, rr, cc)
        return None if best is None else (best[1], best[2])

    def regions(self, min_cells=200):
        """traversable cells in a connected region of >= min_cells (2 m2 on 10 cm cells), cached"""
        if getattr(self, "_big", None) is None:
            from scipy.ndimage import label
            lab, n = label(self.trav, structure=np.ones((3, 3), bool))
            sizes = np.bincount(lab.ravel())
            sizes[0] = 0
            self._big = (sizes >= min_cells)[lab] if n else np.zeros_like(self.trav)
        return self._big

    def planner(self, x, y, escape_m=0.0):
        """Cost-to-go field from the robot (MCP); returns an object with cost(r,c) and path(r,c).
        escape_m > 0: when the robot is off the traversable cells or in a pocket of them (a passage it drove through measures
        under the limit: 11-11 T111, 12 cells at the west end, every candidate unreachable, gave up after 30 s), plan from the
        nearest cell of a large region within escape_m: it got in, so it can get out."""
        start = self.nearest_trav(x, y, 0.8)
        self.escaped = False
        if escape_m > 0 and (start is None or not self.regions()[start]):
            r, c = self.to_cell(x, y)
            n = int(escape_m / self.res)
            big = self.regions()
            rr, cc = np.mgrid[max(0, r - n):min(self.h, r + n + 1), max(0, c - n):min(self.w, c + n + 1)]
            ok = big[rr, cc] & ((rr - r) ** 2 + (cc - c) ** 2 <= n * n)
            if ok.any():
                d2 = np.where(ok, (rr - r) ** 2 + (cc - c) ** 2, np.inf)
                k = np.unravel_index(int(np.argmin(d2)), d2.shape)
                start = (int(rr[k]), int(cc[k]))
                self.escaped = True
        if start is None:
            return None
        m = MCP_Geometric(self.cost, fully_connected=True)
        costs, _ = m.find_costs([start])
        return start, m, costs

    def frontiers(self, min_cells=5, on_free=False):
        """Traversable (on_free: free) cells next to unknown space, grouped into components: [(cells array (k,2))]."""
        unk = self.unk.astype(np.uint8)
        near_unk = cv2.dilate(unk, np.ones((3, 3), np.uint8)) > 0
        mask = ((self.free if on_free else self.trav) & near_unk).astype(np.uint8)
        n, lab, stats, _ = cv2.connectedComponentsWithStats(mask, connectivity=8)
        out = []
        for i in range(1, n):
            if stats[i, cv2.CC_STAT_AREA] >= min_cells:
                out.append(np.argwhere(lab == i))
        return out


class RoomFinder(Node):
    def __init__(self):
        super().__init__("room_finder")
        d = self.declare_parameter
        d("policy", "rule"); d("belief_signs", "none"); d("belief_sign_steer", False); d("sign_seek", 0.0); d("start_scan", False); d("sign_lock", False); d("sign_lock_mode", 2); d("belief_commit", False); d("belief_range", 0.0); d("belief_verify_base", 25.0); d("belief_verify_max", 0.0); d("belief_alpha", 0.85); d("belief_numbers", False); d("belief_period", 8.0); d("belief_weight", 60.0); d("target", 3018); d("lookahead", 2.4); d("arrive_dist", 2.6); d("max_time", 1500.0)
        d("hint_weight", 1.2); d("door_bonus", 5.0); d("door_wall_max", 0.0); d("door_face", True); d("frontier_hint_bonus", 0.0); d("stuck_per_item", False); d("det_reach_m", 0.0); d("stuck_s", 20.0); d("frontier_match_m", 3.0); d("frontier_hold_s", 0.0); d("belief_peak", False); d("skip_looked", False); d("view_half_fov", 0.0); d("sign_base", 30.0); d("sign_belief_w", 0.0); d("belief_guide", False); d("belief_point", False); d("belief_openings", False); d("frontier_on_free", False); d("goal_unlooked", False); d("belief_consensus", 0); d("visit_signs", True); d("visit_doors", True); d("visit_labels", True); d("look_radius", 3.0); d("look_far", 0.0); d("look_open_m", 1.0); d("sign_corridor", False); d("sign_neg_penalty", 0.0); d("sign_neg_exclude", False); d("sign_neg_strip_w", 0.0); d("sign_route_aisle", False); d("escape_m", 0.0); d("keep_trying", False); d("visit_max_pc", 0.0); d("visit_no_back", False); d("look_stop_s", 0.0); d("look_stop_m", 2.5); d("soft_weight", 6.0); d("trav_clear", 0.30); d("trav_occ_m", 0.0); d("grid_res", 0.0); d("viewpoint_fallback_m", 0.0); d("relook", False); d("sign_broad_w", 4.0); d("frontier_min_dist", 0.0); d("trend_weight", 0.0); d("agree_gain", 0.0); d("agree_s", 240.0); d("agree_stall_s", 0.0); d("sign_passed_m", 0.0); d("frontier_block_s", 150.0); d("frontier_bonus", 0.0); d("pass_seen_s", 0.0); d("backtrack_penalty", 0.0); d("view_obj_dist", 0.0); d("view_dwell", 4.0); d("out_dir", ""); d("exit_when_done", False)
        g = lambda k: self.get_parameter(k).value  # noqa: E731
        self.target = str(g("target")).strip()
        tp = roomno.parse(self.target)
        if tp is None:
            raise ValueError("target %r is not a room number (e.g. 3018 or T138)" % self.target)
        self.pre, self.T = tp[0], tp[1]      # series (letters) and number: numeric reasoning only compares one series
        self.target = roomno.norm(self.target)
        self.lookahead, self.arrive, self.max_time = g("lookahead"), g("arrive_dist"), g("max_time")
        self.hint_w, self.door_bonus = g("hint_weight"), g("door_bonus")
        self.door_wall_max = g("door_wall_max")   # >0: a door must have a mapped wall (occupied cell) within this distance (m)
        self.door_face = g("door_face")           # False: go to the door without forcing the final heading (side cameras read the plate)
        self.view_obj_dist, self.view_dwell = g("view_obj_dist"), g("view_dwell")   # >0: a sign/door counts as seen once the robot is that close to it (no need to reach the viewpoint)
        self.backtrack_penalty = g("backtrack_penalty")   # >0: candidates more than 3 m behind the direction of travel lose this many points (no zig-zag between items)
        self._trail = []
        self.belief_guide = g("belief_guide")   # richer belief prompt: how to read sign entries / plates, plus the earlier answers; signs that list the target come first
        self._belief_hist = []
        # frontiers from the free cells next to unknown space instead of the traversable ones: in a 2 m corridor the inflated walls
        # leave a traversable band of ~4 cells, below the 5-cell minimum, so the corridor end did not count as a frontier
        self.frontier_on_free = g("frontier_on_free")
        # a VLM goal gets the weight (agreeing answers among the last N within 10 m) / N: one answer that jumps to the other wing
        # (T113: three answers claimed the numbers grow eastward) no longer outweighs the consistent ones; 0 = off
        self.belief_consensus, self._goal_hist = int(g("belief_consensus")), []
        # visit_*: drive to unread signs / doors with no plate read / labels one digit off the target. Off on the robot since the OCR
        # reads the plates while passing: the visits sent it back along the hallway (11-10)
        self.visit_signs, self.visit_doors, self.visit_labels = g("visit_signs"), g("visit_doors"), g("visit_labels")
        # looked at (no confidence left there): within look_radius of the path (a circle through walls: wall cells and plates need a
        # close pass), plus within look_far in line of sight where it is open (>= look_open_m from obstacles: the lobby).
        # 11-10: a 5 m line of sight everywhere never covered the cells under the walls' inflation (a belief peak at a corridor edge
        # drew the robot back for 150 s) and dismissed the right VLM goal 4 m away before its plate was read (~250 s lost)
        self.look_radius, self.look_far, self.look_open_m = float(g("look_radius")), float(g("look_far")), float(g("look_open_m"))
        # sign_corridor: an arrow points at the mouth of a corridor 1-4 m away which then runs across it (11-10: 'T101~T126' at
        # (-11, -1) and 'T131~T150' at (6, -1) both point north at their corridors' mouths); the cue's direction becomes that corridor.
        # sign_neg_penalty: candidates in the corridor of an entry that does not list the target lose this many points
        self.sign_corridor, self.sign_neg_penalty = g("sign_corridor"), float(g("sign_neg_penalty"))
        self.sign_neg_exclude = bool(g("sign_neg_exclude"))
        self.sign_route_aisle = bool(g("sign_route_aisle"))   # an arrow along the sign's wall: look for the corridor from the aisle
        # in front of the sign, not from the sign itself (inside the wall: A1 r2 'T112~T126 ->' on the main-corridor wall found nothing)
        self.sign_neg_strip_w = float(g("sign_neg_strip_w"))   # > 0: a sign's corridor is the strip this wide on each side of its
        # centre line from the mouth to the corridor's end, not the unbounded +-35 deg wedge (A1 r1: the wedge of 'T101~T126' covered
        # the whole east half, so T127 / T129 behind that corridor ranked low everywhere)   # ablation A1: candidates in a corridor of an entry that does not list the target are removed
        # escape_m > 0: see GridMap.planner; keep_trying: no give-up while the map still has frontiers (blocked goals are freed
        # instead; max_time still ends the run)
        self.escape_m, self.keep_trying = float(g("escape_m")), bool(g("keep_trying"))
        self._route_cache, self._pos_routes, self._neg_routes = {}, [], []
        # visit_max_pc > 0: signs / doors are visited only when the path there is at most this long (m), and with visit_no_back only
        # when they are not behind the direction of travel: read what is on the way, no back and forth
        self.visit_max_pc, self.visit_no_back = float(g("visit_max_pc")), g("visit_no_back")
        # look_stop_s > 0: stand still this long next to an unread door / plate / sign within look_stop_m, once per object (the
        # waypoints carry no speed limit, so stopping is how the OCR / GDINO get a few frames of it)
        self.look_stop_s, self.look_stop_m = float(g("look_stop_s")), float(g("look_stop_m"))
        self._stop, self._stopped, self._stop_after, self._stop_xy = None, set(), 0.0, None
        self._looked_pub_t = 0.0
        # soft_weight: path cost per cell = 1 + soft_weight * (0.9 m - clearance). 6 made a 2 m corridor cost ~4.5x its length, so a
        # frontier 4.5 m down a corridor scored below one 12 m away in a wide hall (11-10 18:08 at T112: turned back south)
        self.soft_weight = float(g("soft_weight"))
        # trav_clear: traversable = free and at least this far from an obstacle / inflated cell of the incoming map. 0.30 on top of
        # the gateway's 0.5 m inflation left passages under ~1.6 m impassable
        self.trav_clear = float(g("trav_clear"))
        # trav_occ_m > 0: passages at least 2 x this wide are traversable, measured from the obstacle hits (passage_trav), whatever
        # the gateway's inflation (trav_clear is then unused). 11-11: 1.1 / 1.12 m passages blocked, 1.2 m passable -> 0.58 with
        # the gateway's 5 cm map and hit positions. The 11-10 runs had the gateway at --inflate 0.5: trav_clear 0.1 passed ~1.3 m
        self.trav_occ_m = float(g("trav_occ_m"))
        # grid_res > 0: the finder works on this grid whatever the map's resolution (a 5 cm map is folded into 10 cm cells after
        # the passage widths are taken from it); every cell-count threshold here was tuned on 10 cm
        self.grid_res = float(g("grid_res"))
        # viewpoint_fallback_m > 0: no free spot 1-2 m in front of a plate / door / sign (2 m corridor, robot along it): the nearest
        # traversable cell within this distance instead (18:08: T113 read once at 0.8 m, its re-read never became a candidate)
        self.viewpoint_fallback_m = float(g("viewpoint_fallback_m"))
        # relook: VLM goals ignored as already looked at become low-score candidates (go there once and look) instead of nothing,
        # so they are checked before giving up (18:08: the VLM named T113's spot 7 times, the robot gave up 6 m from it)
        self.relook, self._ignored_goals = g("relook"), []
        # sign_broad_w: belief-layer weight of sign entries broader than the most specific entry listing the target (that one: 4):
        # 'T112~T121' pointing west must outweigh 'T112~T126' pointing south (18:08)
        self.sign_broad_w = float(g("sign_broad_w"))
        self._route_votes = {}
        # >0: a frontier's goal point is its cheapest reachable cell at least this far from the robot. A corridor frontier starts
        # right at the robot, so its nearest cell was < 0.8 m away and the whole frontier was dropped (11-10 T113: turned back at -26)
        self.frontier_min_dist = float(g("frontier_min_dist"))
        self.goal_unlooked = g("goal_unlooked")   # a VLM goal inside the looked-at area is moved on along robot -> goal
        self.belief_openings = g("belief_openings")   # frontier openings lettered on the VLM map; the VLM names the one to drive through (a sign stands at the hallway it points into)
        self.frontier_match_m = g("frontier_match_m")   # a frontier counts as the same goal when its point moved less than this (it drifts as the map grows)
        self.stuck_s = g("stuck_s")   # seconds without moving 0.35 m before the goal counts as stuck (a person walking by can stop the robot for a while)
        self.frontier_hold_s = g("frontier_hold_s")     # >0: when the current frontier vanishes and everything else scores badly, keep driving to it this long
        self._hold_t = None
        self.det_reach_m = g("det_reach_m")   # >0: doors / signs / plates farther than this from any traversable cell are ignored
        self.view_half_fov = g("view_half_fov")   # rad; >0: only objects inside this half angle around the heading count as seen while passing (3 cameras: yaw 0 / +-90 deg, hfov ~97 deg -> ~2.4)
        self.skip_looked = g("skip_looked")   # signs / doors inside an area the robot has already been within 3 m of are not visited again
        self.belief_peak = g("belief_peak")   # the most confident reachable cell the robot has not looked at is itself a goal (works when no frontier is left there)
        self.sign_base, self.sign_belief_w = g("sign_base"), g("sign_belief_w")   # unread sign: sign_base - path + sign_belief_w * belief (0..1)
        self.belief_point = g("belief_point")   # the VLM also names a map position for the goal: a gaussian blob in the confidence grid instead of only a 90 deg wedge
        # >0: a VLM goal that lies along the arrow of a sign entry listing the target (two independent sources agree) is followed:
        # frontiers gain agree_gain per metre they bring the robot closer to it (a far goal otherwise loses to the frontiers next to the robot)
        self.agree_gain, self.agree_s, self._agree = float(g("agree_gain")), float(g("agree_s")), None
        self.agree_stall_s = float(g("agree_stall_s"))   # >0: an agreed goal the robot gets no 3 m closer to within this time is dropped
        # >0: a sign the robot has already followed (it is this far beyond the sign along the target arrow) no longer locks or agrees:
        # its arrow is the first leg of the route only (T131: past the 'T116~T131 N' sign, its 'T110~T111 E' entry vetoed the right goal)
        self.sign_passed_m = float(g("sign_passed_m"))
        self.trend_weight = g("trend_weight")   # >0: score of frontiers / doors follows the number trend of nearby plates (e.g. T101 -15 m, T103 -25 m -> T106 about -40 m)
        self._trend_log = None
        self.frontier_block_s = g("frontier_block_s")   # how long a stuck frontier stays blocked (items keep 150 s)
        self.frontier_bonus = g("frontier_bonus")   # flat reward for exploring a frontier (signs score ~+27, doors/frontiers are negative without it)
        self.pass_seen_s = g("pass_seen_s")   # >0: a sign / door that stayed within view_obj_dist this many seconds while driving past counts as seen (no detour to read it)
        self._near = {}; self._near_t = None; self._pass_signs = set()
        self.stuck_per_item = g("stuck_per_item")   # True: the stuck window restarts when the goal changes (dwelling at a sign is not "stuck" on the next goal)
        self._prog_item = None
        self.frontier_hint_bonus = g("frontier_hint_bonus")   # >0: score bonus for a frontier that is clearly closer to the hint than the robot
        self.exit_when_done = g("exit_when_done")
        self.out_dir = g("out_dir") or os.path.expanduser("~/raisin_ws/log/room_finder/%s_T%s" % (time.strftime("%Y%m%d_%H%M%S"), self.target))
        os.makedirs(self.out_dir, exist_ok=True)
        self.tfbuf = Buffer(); TransformListener(self.tfbuf, self)
        qos_map = QoSProfile(depth=1, durability=DurabilityPolicy.TRANSIENT_LOCAL)
        self.create_subscription(OccupancyGrid, "/global_costmap/costmap", self._on_map, qos_map)
        self.create_subscription(String, "/room_finder/registry", self._on_registry, 5)
        self.pub_goal = self.create_publisher(PoseStamped, "/room_finder/goal", 5)
        self.pub_goal_yaw = self.create_publisher(PoseStamped, "/room_finder/goal_yaw", 5)
        self.pub_status = self.create_publisher(String, "/room_finder/status", 5)
        self.pub_markers = self.create_publisher(MarkerArray, "/room_finder/markers", 2)
        self.pub_landmarks = self.create_publisher(MarkerArray, "/room_finder/landmarks", 2)
        self._fr_vis, self._lm_t = [], 0.0
        self._dump_t, self._dump_n = 0.0, 0
        self.policy = str(g("policy"))
        self.belief, self.belief_info, self._belief_job, self._belief_t, self._vlm = None, {}, None, 0.0, None
        self.belief_w, self.belief_period = float(g("belief_weight")), float(g("belief_period"))
        self.belief_range, self.belief_numbers = float(g("belief_range")), bool(g("belief_numbers"))
        self.belief_verify_base, self.belief_verify_max, self.belief_alpha = float(g("belief_verify_base")), float(g("belief_verify_max")), float(g("belief_alpha"))
        self.belief_commit = bool(g("belief_commit"))     # evidence-gathering goals (verify / read door) only matter inside the believed region
        # a read sign entry whose range holds the target ("T101~T131 ->" for T127) also adds a wedge along its arrow next to the VLM's
        # answer: the VLM sometimes reasons against a correctly read sign and sends the robot back into the wrong wing
        self.belief_sign_steer = bool(g("belief_sign_steer"))
        self.sign_lock_mode = int(g("sign_lock_mode"))   # 1: only the most specific target entry's cone (+-50 deg) is allowed; 2: only excluded directions are dropped
        self.sign_lock = bool(g("sign_lock"))       # branch lock (needs belief_sign_steer): VLM goals off a target sign's direction are dropped
        self.sign_seek = float(g("sign_seek"))
        self.start_scan = bool(g("start_scan"))     # turn round once at the start (rear blind spot)       # bonus for reading unread signs while no entry lists the target
        self.belief_signs = str(g("belief_signs"))      # none | text (cues in the LLM prompt) | inject (cue wedges in the grid) | both | vlm | steer | rule (sign wedges, no VLM) | off
        from concurrent.futures import ThreadPoolExecutor
        self._pool = ThreadPoolExecutor(max_workers=1)
        self.pub_belief = self.create_publisher(OccupancyGrid, "/room_finder/belief", 1)
        os.makedirs(self.out_dir + "/decisions", exist_ok=True)
        self._say_log, self._top = [], []   # recent log lines and top candidates, shown by the video recorder
        self.gmap, self.reg = None, None
        self.t0 = time.time()
        self.state = "SEARCH"
        self.item = None                 # current goal item {"kind", "xy", "yaw", "id"}
        self.item_t = 0.0
        self.blocked = []                # (x, y, until)
        self._empty_t = None             # when the candidate list became empty
        self.progress = []               # (t, x, y) samples for stuck detection
        self.visited_views = set()       # ("sign", id) / ("door", id) viewpoints already visited
        self.path_len, self.last_xy = 0.0, None
        self.result = None
        self.log = open(self.out_dir + "/finder.log", "a")
        self.create_timer(0.5, self._tick)
        self.say("room_finder up: target=%s out_dir=%s" % (self.target, self.out_dir))

    # ------------------------------------------------------------------ helpers
    def say(self, msg):
        line = "[%5.0fs] %s" % (time.time() - self.t0, msg)
        self.get_logger().info(line)
        self.log.write(line + "\n"); self.log.flush()
        self._say_log = (self._say_log + [line])[-8:]

    def robot_xy(self):
        try:
            t = self.tfbuf.lookup_transform("map", "base_link", rclpy.time.Time()).transform
        except Exception:  # noqa: BLE001
            return None
        q = t.rotation
        yaw = math.atan2(2 * (q.w * q.z + q.x * q.y), 1 - 2 * (q.y * q.y + q.z * q.z))
        return t.translation.x, t.translation.y, yaw

    def _on_map(self, msg):
        try:
            self.gmap = GridMap(msg, inflate=self.trav_clear, weight=self.soft_weight, occ_clear=self.trav_occ_m, grid_res=self.grid_res)
            if self.trav_occ_m > 0 and not self.gmap.subcell and not getattr(self, "_coarse_warned", False):
                self._coarse_warned = True
                self.get_logger().warn("map %.2f m cells without hit positions: walls are known to the cell only, passages from %.2f m "
                                       "wide pass (1.2 m does, narrower ones may too); run the gateway with --map-res 0.05 --subcell 1"
                                       % (float(msg.info.resolution), 2 * self.gmap.occ_clear_used))
        except Exception as e:  # noqa: BLE001
            self.get_logger().warn("map: %r" % e)

    def _on_registry(self, msg):
        self.reg = json.loads(msg.data)

    def is_blocked(self, x, y):
        now = time.time()
        self.blocked = [b for b in self.blocked if b[2] > now]
        return any(math.hypot(bx - x, by - y) < 1.4 for bx, by, _ in self.blocked)

    # ------------------------------------------------------------------ knowledge
    def target_label(self):
        for lb in (self.reg or {}).get("labels", []):
            if lb.get("number") == self.target:
                return lb
        return None

    def _val(self, n):
        """numeric part of room number n when it is in the target's series (same letter prefix), else None"""
        p = roomno.parse(n)
        return p[1] if p is not None and p[0] == self.pre else None

    def number_trend(self):
        """predicted (x, y) of the target from plates in its series within 12 numbers: position is linear in the number.
        None unless two such plates lie at least 4 m apart and the slope is a plausible door spacing (1..8 m per number)."""
        pts = [(v, x, y) for v, x, y in self._known_numbers() if abs(v - self.T) <= 12]
        if len(pts) < 2:
            return None
        v = np.array([p[0] for p in pts], float); xs = np.array([p[1] for p in pts]); ys = np.array([p[2] for p in pts])
        if np.ptp(v) < 1 or math.hypot(np.ptp(xs), np.ptp(ys)) < 4.0:
            return None
        sx, x0 = np.polyfit(v, xs, 1); sy, y0 = np.polyfit(v, ys, 1)
        if not 1.0 <= math.hypot(sx, sy) <= 8.0:
            return None
        return float(sx * self.T + x0), float(sy * self.T + y0)

    def trend_bonus(self, trend, rp, x, y):
        """+ for a spot closer to the predicted target than the robot is, - for one that leads away (|bonus| <= trend_weight)"""
        if trend is None or self.trend_weight <= 0:
            return 0.0
        dr = math.hypot(trend[0] - rp[0], trend[1] - rp[1])
        dc = math.hypot(trend[0] - x, trend[1] - y)
        return self.trend_weight * max(-1.0, min(1.0, (dr - dc) / max(dr, 5.0)))

    def _cue_hit(self, c):
        """does this sign entry list the target (same series, target inside its range)?"""
        return c.get("lo") is not None and (c.get("pre") or "") == self.pre and c["lo"] <= self.T <= c["hi"]

    def hint(self):
        """-> (kind, data) hint about where the target is, or None.
        ('point', (x, y))  predicted from plate numbers;  ('ray', (sx, sy, ux, uy)) from a sign cue."""
        if not self.reg:
            return None
        best_l = {}
        for l in self.reg["labels"]:
            if l.get("number") and self._val(l["number"]) is not None and (l["number"] not in best_l or l.get("score", 0) > best_l[l["number"]].get("score", 0)):
                best_l[l["number"]] = l   # the same plate can exist as several labels; keep the best-supported one
        labels = [(self._val(n), l["x"], l["y"]) for n, l in best_l.items()]
        near = sorted(labels, key=lambda a: abs(a[0] - self.T))
        for i in range(len(near)):
            for j in range(i + 1, len(near)):
                (na, xa, ya), (nb, xb, yb) = near[i], near[j]
                if min(na, nb) < self.T < max(na, nb) and abs(na - self.T) <= 8 and abs(nb - self.T) <= 8 and math.hypot(xa - xb, ya - yb) < 14:   # interpolate only; numbers wrap around corridors, so extrapolating points the wrong way
                    k = (self.T - na) / (nb - na)
                    return "point", (xa + k * (xb - xa), ya + k * (yb - ya))
        fallback = None
        # numbers grow west -> east along the building: extrapolate x from all labels read so far
        if len(labels) >= 4 and max(n for n, _, _ in labels) - min(n for n, _, _ in labels) >= 8:
            ns = np.array([n for n, _, _ in labels], float); xs = np.array([x for _, x, _ in labels], float)
            if np.ptp(ns) > 0 and abs(np.corrcoef(ns, xs)[0, 1]) > 0.5:
                a_, b_ = np.polyfit(ns, xs, 1)
                n0, x0, y0 = near[0]
                if abs(n0 - self.T) <= 30 and a_ > 0:
                    xp = float(np.clip(a_ * self.T + b_, xs.min() - 15, xs.max() + 15))
                    fallback = ("point", (xp, y0))
        rp = self.robot_xy()
        best = None
        for s in self.reg["signs"]:
            for c in s["cues"]:
                if self._cue_hit(c) and c.get("bearing") is not None:
                    dist = math.hypot(s["x"] - rp[0], s["y"] - rp[1]) if rp else 0
                    if best is None or dist < best[0]:
                        best = (dist, (s["x"], s["y"], math.cos(c["bearing"]), math.sin(c["bearing"]), c["place"]))
        if best is None and fallback is None and labels:
            # weakest prior: numbers grow west -> east, so head away from the nearest-numbered plate read so far
            n0, x0, y0 = near[0]
            if abs(n0 - self.T) >= 4:
                fallback = ("point", (x0 + (20.0 if self.T > n0 else -20.0), y0))
        return ("ray", best[1]) if best else fallback

    def _dump_decision(self, gm, cands, best, rp):
        """Save everything needed to replay this decision offline (VLM prompt experiments); does not change behaviour."""
        if time.time() - self._dump_t < 9.0 or len(cands) < 2:
            return
        self._dump_t = time.time()
        try:
            top = sorted(cands, key=lambda c: -c["score"])[:10]
            crops = {}
            cdir = os.path.join(os.path.dirname(self.out_dir), "perception", "crops")
            if os.path.isdir(cdir):
                names = sorted(os.listdir(cdir))
                for s in self.reg.get("signs", []):
                    crops[str(s["id"])] = [n for n in names if n.startswith("sign_s%d_" % s["id"])][-3:]
            rec = {"target": self.target, "elapsed": round(time.time() - self.t0, 1), "robot": [rp[0], rp[1], rp[2]],
                   "cands": [{"note": c["note"], "kind": c["kind"], "xy": [float(c["xy"][0]), float(c["xy"][1])], "score": round(float(c["score"]), 2)} for c in top],
                   "rule_choice": next((i for i, c in enumerate(top) if c is best), None), "hint": self._hint_text(),
                   "reg": self.reg, "sign_crops": crops, "path_len": round(self.path_len, 1)}
            stem = "%s/decisions/d%03d" % (self.out_dir, self._dump_n)
            json.dump(rec, open(stem + ".json", "w"))
            np.savez_compressed(stem + ".npz", occ=np.packbits(gm.occ), free=np.packbits(gm.free), shape=np.array([gm.h, gm.w]),
                                geo=np.array([gm.x0, gm.y0, gm.res]))
            self._dump_n += 1
        except Exception as e:  # noqa: BLE001
            self.get_logger().warn("decision dump failed: %r" % e)

    # ------------------------------------------------------------------ belief policy (paper: Follow the Signs)
    def _belief_bonus(self, x, y):
        return self.belief_w * self.belief.score(x, y) if (self.policy == "belief" and self.belief is not None) else 0.0

    def _belief_query(self, labels, rp, extent, snap=None):
        from mm_dev.room_finder import belief as bel, decide
        from mm_dev.room_finder.vlm import VLM
        if self._vlm is None:
            self._vlm = VLM(os.environ.get("ROOM_FINDER_BELIEF_VLM") or None) if os.environ.get("ROOM_FINDER_BELIEF_VLM") else VLM()
            self._vlm.client = self._vlm.client.with_options(timeout=90.0)      # picture queries on a big model take 20-40 s
        if self.belief_signs in ("vlm", "vlmp", "img", "steer"):
            return self._belief_query_images(labels, snap)
        signs = None
        if self.belief_signs in ("text", "both"):
            signs = []
            for s in (self.reg or {}).get("signs", []):
                ents = [{"place": c["place"], "compass": decide.compass(c["bearing"])} for c in s.get("cues", []) if c.get("bearing") is not None]
                if ents and not s.get("dead"):
                    signs.append({"x": s["x"], "y": s["y"], "entries": ents})
        raw = self._vlm.ask_text(decide.paper_prompt(self.target, labels, rp, extent, regions=bel.DIRS, signs=signs), 500)
        j = self._vlm._json(raw)
        return {"region": str(j.get("region", "")).strip().lower(), "patterns": str(j.get("patterns", ""))[:400],
                "reasoning": str(j.get("reasoning", ""))[:600], "xy": (rp[0], rp[1]), "n_labels": len(labels), "t": time.time()}

    def _belief_query_images(self, labels, snap):
        """Picture-based query: the map as an image plus the cropped photos of the signs seen so far (with where / in which direction they
        were taken). Nothing about the signs is pre-parsed and nothing is injected into the grid: the VLM does all of it."""
        import copy
        from mm_dev.room_finder import belief as bel, decide
        reg, rp = snap["reg"], snap["robot"]
        cdir = os.path.join(os.path.dirname(self.out_dir), "perception", "crops")
        names = sorted(os.listdir(cdir)) if os.path.isdir(cdir) else []
        cand = sorted([s for s in reg.get("signs", []) if not s.get("dead")], key=lambda s: (-s.get("reads", 0), s["id"])) if self.belief_signs in ("vlm", "vlmp") else []
        if self.belief_guide:   # photos of signs that list the target go first (the cap is 3 photos)
            cand.sort(key=lambda s: (0 if any(self._cue_hit(c) for c in s.get("cues", [])) else 1))
        signs, photos = [], []
        for s in cand:
            files = [n for n in names if n.startswith("sign_s%d_" % s["id"])]
            if not files or len(signs) >= 3:
                continue
            ph = cv2.imread(os.path.join(cdir, files[-1]))
            if ph is None:
                continue
            m = max(ph.shape[:2])
            if m > 700:
                ph = cv2.resize(ph, None, fx=700.0 / m, fy=700.0 / m, interpolation=cv2.INTER_AREA)
            nx = s.get("n") or [1.0, 0.0]
            head = math.atan2(-nx[1], -nx[0])
            signs.append({"id": s["id"], "x": s["x"], "y": s["y"], "vx": s["x"] + 2.5 * nx[0], "vy": s["y"] + 2.5 * nx[1],
                          "heading_deg": math.degrees(head) % 360.0, "heading_word": decide.compass(head)})
            photos.append(ph)
        opens = []
        if self.belief_openings:    # the biggest frontier clusters, at least 3 m apart, lettered A..H
            for x, y, n in sorted(snap.get("fronts") or [], key=lambda f: -f[2]):
                if n >= 8 and len(opens) < 8 and all(math.hypot(x - ox, y - oy) > 3.0 for _, ox, oy in opens):
                    opens.append((chr(ord("A") + len(opens)), x, y))
        mp = decide.render_belief_map(snap, reg, rp, signs, grid=self.belief_point, openings=opens)
        if mp is None:
            raise RuntimeError("empty map")
        cm = decide.render_belief_map(snap, reg, rp, signs, conf=snap["conf"], grid=self.belief_point, openings=opens)     # the confidence grid as a picture, same view as the map
        tent = self._tentative_plates(reg, labels) if self.belief_guide else None
        prompt = decide.belief_prompt_images(self.target, labels, rp, signs, bel.DIRS, with_conf=True, guide=self.belief_guide, prev=self._belief_hist, point=self.belief_point, tentative=tent,
                                             openings=opens if self.belief_openings else None)
        raw = self._vlm.ask_multi([mp, cm] + photos, prompt, 1000 if self.belief_point else 700)
        j = self._vlm._json(raw)
        qdir = self.out_dir + "/belief_queries"
        os.makedirs(qdir, exist_ok=True)
        q = len([n for n in os.listdir(qdir) if n.endswith(".json")])
        cv2.imwrite("%s/q%03d_map.jpg" % (qdir, q), mp)
        cv2.imwrite("%s/q%03d_conf.jpg" % (qdir, q), cm)
        json.dump({"prompt": prompt, "answer": raw, "photos": [s["id"] for s in signs], "openings": opens}, open("%s/q%03d.json" % (qdir, q), "w"))
        gxy = None
        try:
            g_ = j.get("goal_xy")
            if self.belief_point and isinstance(g_, (list, tuple)) and len(g_) == 2 and all(abs(float(v)) < 300 for v in g_):
                gxy = (float(g_[0]), float(g_[1]))
        except (TypeError, ValueError):
            gxy = None
        nh = []
        try:
            for c_ in (j.get("not_here") or [])[:4]:
                if self.belief_point and len(c_) == 3 and all(abs(float(v)) < 300 for v in c_):
                    nh.append((float(c_[0]), float(c_[1]), min(15.0, max(2.0, float(c_[2])))))
        except (TypeError, ValueError):
            nh = []
        via = str(j.get("via") or "").strip().upper()[:1]
        vxy = next(((x, y) for L, x, y in opens if L == via), None)
        return {"via": via if vxy else None, "via_xy": vxy, "not_here": nh, "goal_xy": gxy, "region": str(j.get("region", "")).strip().lower(), "patterns": str(j.get("patterns", ""))[:400],
                "reasoning": str(j.get("reasoning", ""))[:600], "xy": (rp[0], rp[1]), "n_labels": len(labels), "t": time.time()}

    def _belief_tick(self, gm, rp):
        from mm_dev.room_finder.belief import BeliefGrid
        if self.belief is None or not self.belief.matches((gm.h, gm.w), gm.x0, gm.y0, gm.res):
            if self.belief is not None and abs(self.belief.res - gm.res) < 1e-9:
                self.belief = self.belief.migrate((gm.h, gm.w), gm.x0, gm.y0)   # the map crop moved: keep what the belief and 'looked' already knew
            else:
                self.belief = BeliefGrid((gm.h, gm.w), gm.x0, gm.y0, gm.res, alpha=self.belief_alpha, look_radius=self.look_radius)
        # apply a finished LLM prediction
        if self._belief_job is not None and self._belief_job.done():
            try:
                info = self._belief_job.result()
                if self.sign_lock and info.get("goal_xy") is not None and not self._in_sign_branch(info["goal_xy"]):
                    # branch lock: a sign entry lists the target, so a VLM goal off that sign's direction is not followed
                    self.say("sign lock: VLM goal (%.0f, %.0f) is off the sign direction, ignored" % info["goal_xy"])
                    info = dict(info, goal_xy=None, via_xy=None, not_here=[], region="")
                if self.goal_unlooked and info.get("goal_xy") is not None and self._in_looked(info["goal_xy"]):
                    # the robot has already looked there, so the answer names no new place. Moving it on along robot -> goal sent it into
                    # the wrong wing when the robot was beyond the goal (11-10 T113: (-6, 3) -> (11, 4)), so the answer is ignored
                    self.say("VLM goal (%.0f, %.0f) lies where the robot has already looked: ignored" % tuple(info["goal_xy"]))
                    self._ignored_goals = (self._ignored_goals + [(float(info["goal_xy"][0]), float(info["goal_xy"][1]), time.time())])[-5:]
                    info = dict(info, goal_xy=None, via=None, via_xy=None, not_here=[], region="")
                if info.get("via_xy") is not None and info.get("goal_xy") is not None and not self._via_toward(info):
                    # the VLM picked the only opening listed although it lies the other way (T113: goal west, via the east corridor)
                    self.say("via %s (%.0f, %.0f) does not lead toward the goal (%.0f, %.0f): ignored" % (
                        (info["via"],) + tuple(info["via_xy"]) + tuple(info["goal_xy"])))
                    info = dict(info, via=None, via_xy=None)
                w_ = 1.0
                if self.belief_consensus > 0 and info.get("goal_xy") is not None:
                    gx_, gy_ = info["goal_xy"]
                    recent = self._goal_hist[-(self.belief_consensus - 1):] if self.belief_consensus > 1 else []
                    support = 1 + sum(1 for hx, hy in recent if math.hypot(hx - gx_, hy - gy_) < 10.0)
                    w_ = support / float(self.belief_consensus)
                    self._goal_hist.append((gx_, gy_))
                    if w_ < 1.0:
                        self.say("VLM goal (%.0f, %.0f) agrees with %d of the last %d answers: weight %.2f" % (gx_, gy_, support - 1, len(recent), w_))
                if self.agree_gain > 0 and info.get("goal_xy") is not None:
                    s_ = self._sign_agrees(info["goal_xy"])
                    if s_ is not None:
                        self._agree = (info["goal_xy"][0], info["goal_xy"][1], time.time())
                        self._agree_best = (float("inf"), time.time())
                        self.say("VLM goal (%.0f, %.0f) agrees with the target sign at (%.0f, %.0f): heading there" % (tuple(info["goal_xy"]) + s_))
                if (self.belief.add_point(info["goal_xy"][0], info["goal_xy"][1], weight=w_) if info.get("goal_xy") is not None else
                        self.belief.add_prediction(info["region"], info["xy"][0], info["xy"][1], range_m=self.belief_range)):
                    self.belief_info = info
                    self._belief_hist.append((info["region"], info["xy"][0], info["xy"][1]))
                    if info.get("via_xy") is not None and info.get("goal_xy") is not None:   # the hallway entrance the VLM chose pulls the robot in, even when goal_xy is deep in unexplored space
                        self.belief.add_point(info["via_xy"][0], info["via_xy"][1], sigma=3.0, decay=False, weight=w_)
                    if self.belief_point:
                        prot = self._protected_plates() + ([info["via_xy"]] if info.get("via_xy") is not None else [])
                        self.belief.set_exclusions([c for c in (info.get("not_here") or [])
                                                    if not any(math.hypot(px - c[0], py - c[1]) <= c[2] + 2.0 for px, py in prot)])
                    self.say("LLM belief: goal is %s of (%.0f, %.0f)%s -- %s" % (info["region"], info["xy"][0], info["xy"][1],
                             ("" if info.get("goal_xy") is None else " at (%.0f, %.0f)" % info["goal_xy"]) +
                             ("" if info.get("via_xy") is None else " via %s (%.0f, %.0f)" % (info["via"], info["via_xy"][0], info["via_xy"][1])), info["patterns"][:110]))
            except Exception as e:  # noqa: BLE001
                self.get_logger().warn("belief query failed: %r" % e)
            self._belief_job = None
        if self.look_far > 0:
            self.belief.look(rp[0], rp[1], gm.occ, gm.clear >= self.look_open_m, self.look_far)
        else:
            self.belief.look(rp[0], rp[1])
        if self.belief_signs in ("steer", "rule") or (self.belief_sign_steer and self.belief_signs in ("vlm", "vlmp")):
            pos, neg, desc = [], [], []
            pos_r, neg_r, effs = [], [], {}

            def cues_of(s):
                return [c for c in s.get("cues", []) if c.get("bearing") is not None and c.get("lo") is not None]

            def eff(s, c):
                """(origin x, y; direction for the belief layer; direction seen from the sign; corridor route or None) of a cue;
                None while sign_corridor waits for the map around its arrow (the cue is left out until then)"""
                rt = self._cue_route(gm, s["x"], s["y"], c["bearing"], (s["id"], c["place"]), c.get("bearing2"), c.get("view"),
                                     s.get("n") if self.sign_route_aisle else None) if self.sign_corridor else None
                if rt == "wait":
                    return None
                if rt is None:
                    return (round(s["x"], 1), round(s["y"], 1)), c["bearing"], c["bearing"], None
                qx, qy = rt[0] + 6.0 * math.cos(rt[2]), rt[1] + 6.0 * math.sin(rt[2])
                return (round(rt[0], 1), round(rt[1], 1)), rt[2], math.atan2(qy - s["y"], qx - s["x"]), rt

            signs = [s for s in (self.reg or {}).get("signs", []) if not s.get("dead") and s.get("valid", True)]
            for s in signs:
                for i, c in enumerate(cues_of(s)):
                    effs[(s["id"], i)] = eff(s, c)
            spans_hit = [c["hi"] - c["lo"] for s in signs for i, c in enumerate(cues_of(s)) if self._cue_hit(c) and effs[(s["id"], i)] is not None]
            locks, spans = [], []   # locks: signs with an entry that lists the target: (x, y, bearings to the target, bearings of the other entries)
            for s in signs:
                cues = cues_of(s)
                has = [c for c in cues if self._cue_hit(c)]
                hit_b, other_b = [], []
                for i, c in enumerate(cues):
                    e = effs[(s["id"], i)]
                    if e is None:
                        continue
                    org, lb_, sb, rt = e
                    if c in has:      # the entry lists the goal: head that way (full weight for the most specific entry)
                        pos.append(org + (round(lb_, 2), 4.0 if c["hi"] - c["lo"] <= min(spans_hit) else self.sign_broad_w, math.pi / 5, 45.0))
                        desc.append("S%d '%s' -> goal %.0f deg%s" % (s["id"], c["place"], math.degrees(lb_),
                                                                     "" if rt is None else " (corridor from (%.1f, %.1f))" % org))
                        if rt is not None:
                            pos_r.append(rt)
                        hit_b.append(sb)
                        spans.append((c["hi"] - c["lo"], (s["x"], s["y"], sb)))
                    else:
                        # another area: the target is probably not that way, but not certainly (a sign does not list every room; 11-11
                        # T111 was by 'T112~T126'). Soft for every entry alike: the belief there is scaled down (x0.6, x0.2 when another
                        # entry of the sign lists the target) and candidates there rank lower (sign_neg_penalty); none is removed
                        neg.append(org + (round(lb_, 2), 0.2 if has else 0.6, math.pi / 8, 45.0))
                        if rt is not None:
                            neg_r.append(rt)
                            desc.append("S%d '%s' makes the corridor %.0f deg from (%.1f, %.1f) unlikely" % (s["id"], c["place"], math.degrees(lb_), org[0], org[1]))
                        other_b.append(sb)
                if hit_b:
                    locks.append((s["x"], s["y"], hit_b, other_b))
            self._pos_routes, self._neg_routes = pos_r, neg_r
            if self.sign_neg_strip_w > 0:
                self._pos_strips = [self._corridor_line(gm, rt) for rt in pos_r]
                self._neg_strips = [self._corridor_line(gm, rt) for rt in neg_r]
                for rt, ln in zip(neg_r, self._neg_strips):
                    desc.append("corridor from (%.1f, %.1f) ends (%.1f, %.1f), %.0f m" % (rt[0], rt[1], ln[-1][0], ln[-1][1], self._line_len(ln)))
            self._lock_cones = locks
            self._lock_cones_v1 = [c for sp, c in spans if sp == min(sp_ for sp_, _ in spans)]   # the most specific entries ("T127" beats "T101~T131")
            sig = (tuple(pos), tuple(neg))
            if sig != getattr(self, "_steer_sig", None):
                self._steer_sig = sig
                if desc:
                    self.say("sign steering: %s; %d excluded directions" % ("; ".join(desc)[:200], len(neg)))
            if self.belief_signs in ("steer", "rule"):
                self.belief.set_steer(pos, neg, sig)
            else:   # with the VLM: only the entries that list the goal, as a fixed layer (the VLM's exclusions keep X)
                self.belief.set_signs(pos, sig)
        if self.belief_signs in ("inject", "both"):
            wedges = []
            for s in (self.reg or {}).get("signs", []):
                if s.get("dead") or s.get("reads", 0) < 2:      # a single parse is not trusted
                    continue
                for c in s.get("cues", []):
                    if c.get("bearing") is None or c.get("lo") is None:
                        continue
                    w = 2.0 if self._cue_hit(c) else -0.6   # the arrow of an entry that excludes the target points away from it
                    wedges.append((round(s["x"], 1), round(s["y"], 1), round(c["bearing"], 2), w, math.pi / 6, 45.0))
            self.belief.set_signs(wedges, tuple(wedges))
        if self._belief_job is None and time.time() - self._belief_t >= self.belief_period and self.belief_signs not in ("rule", "off"):   # rule: signs + numbers only, no VLM; off: plain exploration
            labels = [(n, x, y) for n, x, y in self._known_numbers_all()]
            if labels or (self.belief_guide and (self.reg or {}).get("signs")):   # signs alone are enough to ask (no waiting for a plate)
                self._belief_t = time.time()
                known = gm.occ | gm.free
                rr, cc = np.nonzero(known)
                ext = (gm.x0 + cc.min() * gm.res, gm.x0 + cc.max() * gm.res, gm.y0 + rr.min() * gm.res, gm.y0 + rr.max() * gm.res) if rr.size else (0, 0, 0, 0)
                snap = None
                if self.belief_signs in ("vlm", "vlmp", "img", "steer"):
                    import copy
                    snap = {"occ": gm.occ.copy(), "free": gm.free.copy(), "looked": self.belief.looked.copy(), "conf": self.belief.C.copy(), "res": gm.res, "x0": gm.x0,
                            "y0": gm.y0, "reg": copy.deepcopy(self.reg), "robot": (rp[0], rp[1], rp[2] if len(rp) > 2 else 0.0), "fronts": list(self._fr_vis)}
                self._belief_job = self._pool.submit(self._belief_query, labels, (rp[0], rp[1]), ext, snap)

    def _cue_route(self, gm, sx, sy, b, vote_key=None, b2=None, view=None, nrm=None):
        """sign_corridor: (x, y of the corridor mouth, corridor bearing) the arrow means, or None (see _cue_route_once). Recomputed
        every 5 s as the map grows; with vote_key the answer is the majority of the corridors found so far for that sign entry
        (18:08: 'T101~T126' flipped between west, east and the raw arrow while the map filled in). Only corridors found from the
        current reading of the entry vote: a new read whose arrow is > 15 deg off drops the older ones (11-11 T140: 'T131~T150'
        first read 43 deg off gave a corridor back into the lobby, and it outlived the corrected read for 1000 s because the
        corrected arrow found no corridor of its own)"""
        key = (round(sx, 1), round(sy, 1), round(b, 2), None if b2 is None else round(b2, 2))
        hit = self._route_cache.get(key)
        if hit is not None and time.time() - hit[0] < 5.0:
            out = hit[1]
        else:
            if nrm is not None and abs(math.cos(b - math.atan2(nrm[1], nrm[0]))) < 0.5:
                sx, sy = self._aisle_point(gm, sx, sy, math.atan2(nrm[1], nrm[0]))
            out = self._cue_route_bent(gm, sx, sy, b, b2, view) if (b2 is not None and view is not None) else self._cue_route_once(gm, sx, sy, b)
            self._route_cache[key] = (time.time(), out)
            if vote_key is not None and isinstance(out, tuple):
                self._route_votes.setdefault(vote_key, []).append((out, b, b2))
        if vote_key is None:
            return out

        def near(u, v):
            if u is None or v is None:
                return u is None and v is None
            return abs((u - v + math.pi) % (2 * math.pi) - math.pi) <= math.radians(15)
        allv = self._route_votes.get(vote_key, [])
        cur = [v for v in allv if near(v[1], b) and near(v[2], b2)]
        if len(cur) != len(allv):
            self._route_votes[vote_key] = cur
            if any(isinstance(v[0], tuple) for v in allv):
                self.say("S%s '%s': arrow re-read %.0f deg -> its earlier corridors (%d) dropped" % (
                    vote_key[0], vote_key[1], math.degrees(b), len(allv) - len(cur)))
        votes = [v[0] for v in cur][-20:]
        if not votes:
            return out

        def same(u, v):
            return abs((u[2] - v[2] + math.pi) % (2 * math.pi) - math.pi) < math.radians(45)
        best = max(range(len(votes)), key=lambda i: (sum(same(votes[i], u) for u in votes), i))
        return [v for v in votes if same(v, votes[best])][-1]

    def _cue_route_bent(self, gm, sx, sy, b1, b2, view):
        """a bent arrow ('left-then-straight' ...): from where a reader stands (1 m in front of the sign) walk along the first leg
        (<= 8 m over free cells); the first spot whose second-leg side has >= 2.5 m of free cells is where the route turns:
        (x, y, second-leg bearing). 'wait' when the walk or a second-leg side runs into unknown space first, None when the walk
        ends at a wall (the first leg is then taken as it is). 11-10 18:40: 'T112~T121' (left, then into the corridor ahead)
        was read as plain 'left' and the robot went on left."""
        ox, oy = sx - math.cos(view), sy - math.sin(view)
        entered, pending = False, False
        for d in np.arange(0.0, 8.01, 0.2):
            px, py = ox + math.cos(b1) * d, oy + math.sin(b1) * d
            r, c = gm.to_cell(px, py)
            if not gm.inside(r, c):
                return "wait"
            if not gm.free[r, c]:
                if not gm.occ[r, c]:
                    return "wait"        # unknown space on the first leg
                if entered:
                    return "wait" if pending else None
                continue                 # still in an inflated band next to the reader's spot
            entered = True
            n, end, need = 0, "far", int(round(2.5 / gm.res))    # round: int(2.5 / 0.1) is 24
            for k in range(1, need + 1):
                r2, c2 = gm.to_cell(px + math.cos(b2) * k * gm.res, py + math.sin(b2) * k * gm.res)
                if not gm.inside(r2, c2) or not gm.free[r2, c2]:
                    end = "wall" if (gm.inside(r2, c2) and gm.occ[r2, c2]) else "unknown"
                    break
                n += 1
            if n >= need:
                return float(px), float(py), float(b2)
            pending = pending or end == "unknown"
        return "wait" if pending else None

    @staticmethod
    def _aisle_point(gm, sx, sy, a):
        """the middle of the free run in front of a wall sign along its face normal a (first free cell within 1.5 m, run up to 4 m);
        the sign itself when no free cell is found"""
        run = []
        for k in range(0, int(5.5 / gm.res) + 1):
            px, py = sx + math.cos(a) * k * gm.res, sy + math.sin(a) * k * gm.res
            r, c = gm.to_cell(px, py)
            ok = gm.inside(r, c) and gm.free[r, c]
            if ok:
                run.append((px, py))
            elif run or k * gm.res > 1.5:
                break
            if run and len(run) * gm.res >= 4.0:
                break
        if not run:
            return sx, sy
        return run[len(run) // 2]

    def _cue_route_once(self, gm, sx, sy, b):
        """walk up to 4 m from the sign along its arrow over free cells; at the first spot where one side is a narrow corridor
        (>= 2.5 m of free cells, < 25 % of them more than 1 m from an obstacle) and the other side is clearly wider (>= 2.5 m and
        15 points more wide cells) or a wall (an obstacle within 1.5 m), the arrow means that corridor: (x, y, bearing).
        None: the arrow as it is (no side corridor, e.g. it points along a corridor). 'wait': next to open space a side runs into
        unknown space within 2.5 m, i.e. the corridor is not mapped yet (18:08: 'T101~T126' at 141 s fell back to its raw arrow,
        north, and sent the robot into the north lobby)"""
        def side(px, py, a):
            vx, vy = math.cos(a), math.sin(a)
            n = wide = 0
            end = "far"
            for k in range(1, int(6.0 / gm.res) + 1):
                r, c = gm.to_cell(px + vx * k * gm.res, py + vy * k * gm.res)
                if not gm.inside(r, c):
                    end = "unknown"
                    break
                if not gm.free[r, c]:
                    end = "wall" if gm.occ[r, c] else "unknown"
                    break
                n += 1
                wide += bool(gm.clear[r, c] > 1.0)
            return n * gm.res, (wide / n if n else 0.0), end

        entered, wait = False, False
        for d in np.arange(0.2, 4.01, 0.2):
            px, py = sx + math.cos(b) * d, sy + math.sin(b) * d
            r, c = gm.to_cell(px, py)
            if not gm.inside(r, c):
                return None
            if not gm.free[r, c]:
                if entered:
                    return None      # the far wall: no side corridor on the way
                continue             # the sign's own wall and its inflation
            entered = True
            sides = [(a,) + side(px, py, a) for a in (b + math.pi / 2, b - math.pi / 2)]
            narrow = [s_ for s_ in sides if s_[1] >= 2.5 and s_[2] < 0.25]
            if len(narrow) == 2:
                return None          # a T junction: both ways are corridors
            if len(narrow) == 1:
                o = sides[1] if sides[0] is narrow[0] else sides[0]
                if (o[1] >= 2.5 and o[2] >= narrow[0][2] + 0.15) or (o[3] == "wall" and o[1] < 1.5):
                    return float(px), float(py), float((narrow[0][0] + math.pi) % (2 * math.pi) - math.pi)
            for s_, o in ((sides[0], sides[1]), (sides[1], sides[0])):
                if s_[3] == "unknown" and s_[1] < 2.5 and o[1] >= 2.5 and o[2] >= 0.4:
                    wait = True
        return "wait" if wait else None

    @staticmethod
    def _line_len(ln):
        return sum(math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(ln[:-1], ln[1:]))

    def _corridor_line(self, gm, rt, step=0.5, max_m=60.0):
        """centre line of the corridor a route enters: from the mouth along its bearing in 0.5 m steps, re-centred between the side
        walls where both are within 2 m, until the cell ahead is an obstacle (the corridor's end) or 60 m; unknown cells count as
        open, so an unexplored corridor runs on until the map closes it"""
        x, y, h = rt
        ln = [(x, y)]

        def wall(px, py, a, lim=2.0):
            for k in range(1, int(lim / gm.res) + 1):
                r, c = gm.to_cell(px + math.cos(a) * k * gm.res, py + math.sin(a) * k * gm.res)
                if not gm.inside(r, c) or gm.occ[r, c]:
                    return k * gm.res
            return None
        for _ in range(int(max_m / step)):
            nx_, ny_ = x + math.cos(h) * step, y + math.sin(h) * step
            for o in (0.0, 0.4, -0.4, 0.8, -0.8):   # side-step a person or a bench; only a blocked width ends the corridor
                ox, oy = nx_ - math.sin(h) * o, ny_ + math.cos(h) * o
                r, c = gm.to_cell(ox, oy)
                if gm.inside(r, c) and not gm.occ[r, c]:
                    break
            else:
                break
            nx_, ny_ = ox, oy
            dl, dr = wall(nx_, ny_, h + math.pi / 2), wall(nx_, ny_, h - math.pi / 2)
            if dl is not None and dr is not None:
                off = (dl - dr) / 2.0
                nx_, ny_ = nx_ - math.sin(h) * off, ny_ + math.cos(h) * off
            x, y = nx_, ny_
            ln.append((x, y))
        return ln

    def _route_penalty(self, x, y):
        """sign_neg_penalty when (x, y) lies in the corridor of a sign entry that does not list the target (+-35 deg from its mouth,
        > 1.5 m in) and in no corridor of an entry that does: the target is probably not there, so it ranks lower, never removed"""
        if self.sign_neg_penalty <= 0 or not self._neg_routes:
            return 0.0

        def inside(rt):
            dx, dy = x - rt[0], y - rt[1]
            return math.hypot(dx, dy) > 1.5 and abs((math.atan2(dy, dx) - rt[2] + math.pi) % (2 * math.pi) - math.pi) <= math.radians(35)

        def in_strip(ln):
            if math.hypot(x - ln[0][0], y - ln[0][1]) <= 1.5:
                return False
            for a, b in zip(ln[:-1], ln[1:]):
                vx, vy = b[0] - a[0], b[1] - a[1]
                u = max(0.0, min(1.0, ((x - a[0]) * vx + (y - a[1]) * vy) / max(vx * vx + vy * vy, 1e-9)))
                if math.hypot(x - a[0] - u * vx, y - a[1] - u * vy) <= self.sign_neg_strip_w:
                    return True
            return False
        if self.sign_neg_strip_w > 0:
            neg, pos = getattr(self, "_neg_strips", []), getattr(self, "_pos_strips", [])
            if any(in_strip(ln) for ln in neg if len(ln) > 1) and not any(in_strip(ln) for ln in pos if len(ln) > 1):
                return self.sign_neg_penalty
            return 0.0
        if any(inside(rt) for rt in self._neg_routes) and not any(inside(rt) for rt in self._pos_routes):
            return self.sign_neg_penalty
        return 0.0

    def _active_cones(self):
        cones = getattr(self, "_lock_cones", None) or []
        rp = self.robot_xy() if self.sign_passed_m > 0 else None
        if rp is None:
            return cones
        return [c for c in cones if not all((rp[0] - c[0]) * math.cos(h) + (rp[1] - c[1]) * math.sin(h) > self.sign_passed_m for h in c[2])]

    def _sign_agrees(self, xy):
        """(x, y) of a sign whose entry listing the target points at xy (+-40 deg, > 6 m away), else None"""
        for sx, sy, hit, _ in self._active_cones():
            dx, dy = xy[0] - sx, xy[1] - sy
            if math.hypot(dx, dy) > 6.0 and any(abs((math.atan2(dy, dx) - h + math.pi) % (2 * math.pi) - math.pi) <= math.radians(40) for h in hit):
                return sx, sy
        return None

    def _agree_bonus(self, rp, x, y):
        if self._agree is None:
            return 0.0
        gx, gy, t = self._agree
        dr = math.hypot(gx - rp[0], gy - rp[1])
        if dr < self._agree_best[0] - 3.0:
            self._agree_best = (dr, time.time())
        stall = self.agree_stall_s > 0 and time.time() - self._agree_best[1] > self.agree_stall_s
        if dr < 6.0 or time.time() - t > self.agree_s or stall:
            self.say("agreed goal (%.0f, %.0f) %s" % (gx, gy, "reached" if dr < 6.0 else "dropped: no progress" if stall else "expired"))
            self._agree = None
            return 0.0
        return self.agree_gain * (dr - math.hypot(gx - x, gy - y))

    def _in_sign_branch(self, xy):
        """False when xy lies where a sign that lists the target sends the other entries and not the target (arrow +-40 deg, > 6 m away).
        A sign points along the first leg of the route, so only its excluded directions are ruled out, not everything off its arrow."""
        def ang(a, b):
            return abs((a - b + math.pi) % (2 * math.pi) - math.pi)
        if self.sign_lock_mode == 1:
            cones = getattr(self, "_lock_cones_v1", None)
            return not cones or any(math.hypot(xy[0] - sx, xy[1] - sy) < 6.0 or ang(math.atan2(xy[1] - sy, xy[0] - sx), br) <= math.radians(50)
                                    for sx, sy, br in cones)
        for sx, sy, hit, other in self._active_cones():
            dx, dy = xy[0] - sx, xy[1] - sy
            if math.hypot(dx, dy) < 6.0:
                continue
            b = math.atan2(dy, dx)
            if any(ang(b, o) <= math.radians(40) for o in other) and not any(ang(b, h) <= math.radians(40) for h in hit):
                return False
        return True

    @staticmethod
    def _via_toward(info, margin=1.0):
        """the opening is on the way: from it the goal is at least `margin` m closer than from the robot"""
        (rx, ry), (gx, gy), (vx, vy) = info["xy"][:2], info["goal_xy"], info["via_xy"]
        return math.hypot(vx - gx, vy - gy) <= math.hypot(rx - gx, ry - gy) - margin

    def _in_looked(self, xy):
        """the cell at xy has been looked at (looked-at cells get no confidence)"""
        b = self.belief
        if b is None:
            return False
        r, c = b.cell(xy[0], xy[1])
        return bool(0 <= r < b.shape[0] and 0 <= c < b.shape[1] and b.looked[r, c] > 0)

    def _known_numbers_all(self):
        best = {}
        for l in (self.reg or {}).get("labels", []):
            n = l.get("number")
            if n and roomno.parse(n) is not None and (n not in best or l.get("score", 0) > best[n].get("score", 0)):
                best[n] = l
        return [(n, l["x"], l["y"]) for n, l in best.items()]

    def _hint_text(self):
        if self.policy == "belief":
            b = self.belief_info
            return ("LLM belief: goal %s of (%.0f,%.0f)" % (b["region"], b["xy"][0], b["xy"][1])) if b else "LLM belief: no prediction yet (frontier exploration)"
        h = self.hint()
        if h is None:
            return "none (explore)"
        if h[0] == "ray":
            sx, sy, ux, uy, place = h[1]
            return "sign ray: '%s' from (%.0f,%.0f) heading %.0f deg" % (place, sx, sy, math.degrees(math.atan2(uy, ux)))
        return "point (%.0f, %.0f) from plate numbers" % (h[1][0], h[1][1])

    def _known_numbers(self):
        """accepted plate numbers, one label per number: [(n, x, y)]"""
        best = {}
        for l in (self.reg or {}).get("labels", []):
            n = l.get("number")
            if n and self._val(n) is not None and abs(self._val(n) - self.T) <= 40 and (n not in best or l.get("score", 0) > best[n].get("score", 0)):
                best[n] = l
        return [(self._val(n), l["x"], l["y"]) for n, l in best.items()]

    def number_penalty(self, known, x, y):
        """Numbers change by about one per door (~3.4 m) along a corridor, so near a plate read as n the numbers at (x, y)
        are about n +- d/3. If the target is farther than that from every nearby plate, the target is not here:
        e.g. a corridor read as 3025 ... 3038 cannot contain 3022. Returns a score penalty (0 = plausible / no information)."""
        near = [(n, math.hypot(x - px, y - py)) for n, px, py in known if math.hypot(x - px, y - py) < 6.0]
        if not near:
            return 0.0
        # the most favourable nearby plate decides: the target must be reachable from at least one of them
        viol = min(abs(n - self.T) - (d / 3.4 + 1.5) for n, d in near)
        return min(80.0, 12.0 * viol) if viol > 0 else 0.0

    @staticmethod
    def hint_distance(hint, x, y):
        if hint is None:
            return 0.0
        kind, d = hint
        if kind == "point":
            return math.hypot(x - d[0], y - d[1])
        sx, sy, ux, uy = d[:4]
        s = (x - sx) * ux + (y - sy) * uy
        if s <= 0:
            return math.hypot(x - sx, y - sy) + 0.5 * (-s)
        return abs((x - sx) * uy - (y - sy) * ux)

    # ------------------------------------------------------------------ candidate generation
    def viewpoint(self, gm, x, y, nrm, rp, dists=(1.4, 1.1, 1.8, 2.2, 0.9)):
        """Free spot in front of a door / sign at (x, y); nrm = unit normal toward the viewer (or None)."""
        cands = []
        if nrm is not None:
            cands.append((nrm[0], nrm[1]))
        v = (rp[0] - x, rp[1] - y); n = math.hypot(*v) or 1.0
        cands.append((v[0] / n, v[1] / n))
        for nx, ny in cands:
            for dist in dists:
                px, py = x + nx * dist, y + ny * dist
                r, c = gm.to_cell(px, py)
                if gm.inside(r, c) and gm.trav[r, c]:
                    return px, py, math.atan2(-ny, -nx)
        if self.viewpoint_fallback_m > 0:
            near = gm.nearest_trav(x, y, self.viewpoint_fallback_m)
            if near is not None:
                px, py = gm.to_xy(*near)
                return px, py, math.atan2(y - py, x - px)
        return None

    def _reach_filter(self, reg):
        gm = self.gmap
        ok = lambda o: gm.nearest_trav(o["x"], o["y"], self.det_reach_m) is not None   # noqa: E731
        out = dict(reg)
        # room plates are kept: their number is evidence for the numbering even when the position is off (a plate read from
        # 4 m away was placed 2.3 m behind the wall); doors and signs outside the reach are dropped (they become goals)
        for k in ("doors", "signs"):
            out[k] = [o for o in reg.get(k, []) if ok(o)]
        return out

    def _tentative_plates(self, reg, labels):
        """plates read only once (not accepted yet) in the target's series within 12 numbers: [(number, x, y)]. Passing a plate at speed often gives one read."""
        have = {n for n, _, _ in labels}
        out = {}
        for lb in reg.get("labels", []):
            if lb.get("number"):
                continue
            for n, w in lb.get("reads", []):
                v = self._val(n)
                if v is not None and abs(v - self.T) <= 12 and n not in have and w >= 0.4 and (n not in out or w > out[n][3]):
                    out[n] = (n, lb["x"], lb["y"], w)
        return [(n, x, y) for n, x, y, _ in out.values()]

    def _protected_plates(self):
        """positions of plates (accepted or tentative) whose number is within 12 of the target: an area holding one cannot be 'not here'"""
        pts = []
        for lb in (self.reg or {}).get("labels", []):
            ns = [lb["number"]] if lb.get("number") else [n for n, w in lb.get("reads", []) if w >= 0.4]
            if any((self._val(n) is not None and abs(self._val(n) - self.T) <= 12) for n in ns):
                pts.append((lb["x"], lb["y"]))
        return pts

    def _looked(self, gm, x, y):
        if not self.skip_looked or self.belief is None or not self.belief.matches((gm.h, gm.w), gm.x0, gm.y0, gm.res):
            return False
        r, c = gm.to_cell(x, y)
        return bool(gm.inside(r, c) and self.belief.looked[r, c] > 0)

    def candidates(self, gm, field, rp):
        start, mcp, costs = field
        hint = self.hint()
        out = []
        self._fr_vis = []
        trend = self.number_trend() if self.trend_weight > 0 else None
        if trend is not None and (self._trend_log is None or math.hypot(trend[0] - self._trend_log[0], trend[1] - self._trend_log[1]) > 3.0):
            self._trend_log = trend
            self.say("number trend: %s is expected near (%.1f, %.1f)" % (self.target, trend[0], trend[1]))
        known = self._known_numbers()
        if self.policy == "belief":     # no sign rays, no number rules: the LLM-driven confidence grid replaces them
            hint, known = None, (known if self.belief_numbers else [])

        def path_cost(x, y):
            r, c = gm.to_cell(x, y)
            if not gm.inside(r, c) or not np.isfinite(costs[r, c]):
                return None
            return float(costs[r, c]) * gm.res

        reg = self.reg or {}
        head = None   # direction of the last ~3 m of travel (visit_no_back)
        if self.visit_no_back and len(self._trail) > 4:
            tx, ty = self._trail[max(0, len(self._trail) - 6)]
            if math.hypot(rp[0] - tx, rp[1] - ty) > 1.5:
                head = math.atan2(rp[1] - ty, rp[0] - tx)

        def on_way(x, y, pc):
            if self.visit_max_pc > 0 and pc > self.visit_max_pc:
                return False
            return head is None or math.hypot(x - rp[0], y - rp[1]) < 1.0 or \
                abs((math.atan2(y - rp[1], x - rp[0]) - head + math.pi) % (2 * math.pi) - math.pi) <= math.radians(100)

        if self.start_scan and ("scan", 0) not in self.visited_views and len(rp) > 2:
            # the three cameras do not see behind the robot: turn round once at the start so the signs there are seen too
            self._scan_pose = getattr(self, "_scan_pose", None) or (rp[0], rp[1], (rp[2] + math.pi + math.pi) % (2 * math.pi) - math.pi)
            out.append({"kind": "verify", "id": -1, "xy": self._scan_pose[:2], "yaw": self._scan_pose[2], "score": 1e6, "key": ("scan", 0), "note": "look back"})
        # no sign entry lists the target yet: reading the signs in view beats exploring blind (the lobby signs tell which wing)
        seek = self.sign_seek if not any(self._cue_hit(c) for s in reg.get("signs", []) if not s.get("dead") for c in s.get("cues", [])) else 0.0
        # (2) signs whose cues have not been read
        for s in (reg.get("signs", []) if self.visit_signs else []):
            if self.policy == "belief" and self.belief_signs in ("none", "img", "vlmp", "off"):
                break
            key = ("sign", s["id"], s["reads"] // 3)   # a sign whose reads were unusable may be revisited
            if self._looked(gm, s["x"], s["y"]) and not (self.item is not None and self.item.get("key") == key):
                continue
            if s["cues"] or s.get("dead") or not s.get("valid", True) or key in self.visited_views or s["reads"] >= 6 or s["id"] in self._pass_signs:
                continue
            vp = self.viewpoint(gm, s["x"], s["y"], s.get("n"), rp, dists=(2.0, 1.6, 2.6, 3.0))
            if vp and not self.is_blocked(vp[0], vp[1]):
                pc = path_cost(vp[0], vp[1])
                if pc is not None and pc < 35 and on_way(vp[0], vp[1], pc):
                    out.append({"kind": "sign", "id": s["id"], "xy": vp[:2], "yaw": vp[2], "obj": (s["x"], s["y"]), "score": self.sign_base + seek - pc - self._route_penalty(s["x"], s["y"]) + (self.sign_belief_w * self.belief.score(s["x"], s["y"]) if (self.sign_belief_w > 0 and self.belief is not None) else 0.0),
                                "key": key, "note": "read sign S%d" % s["id"]})
        # labels with a read one digit off the target (OCR confuses 2/7, 3/8 ...): re-read them from close range
        for lb in reg.get("labels", []):
            if lb.get("number") == self.target or (lb.get("number") and lb.get("score", 0) >= 2.0):
                continue   # confidently read as another room (neighbouring numbers differ by one digit too)
            near = any(len(n) == len(self.target) and sum(a != b for a, b in zip(n, self.target)) <= 1
                       for n, _ in lb["reads"])
            if not near:
                continue
            exact = any(n == self.target for n, _ in lb["reads"])   # a direct hit outranks any hint
            if not exact and not self.visit_labels:
                continue   # visit_labels off: only a read of the target itself is worth a detour (to confirm it)
            for k in range(3 if exact else 2):
                key = ("verify", lb["id"], k)
                if key in self.visited_views:
                    continue
                vp = self.viewpoint(gm, lb["x"], lb["y"], None, rp, dists=(1.5, 1.2, 2.0))
                if vp and not self.is_blocked(vp[0], vp[1]):
                    pc = path_cost(vp[0], vp[1])
                    if pc is not None and pc < 45 and (exact or self.belief_verify_max <= 0 or pc <= self.belief_verify_max):
                        out.append({"kind": "verify", "id": lb["id"], "xy": vp[:2], "yaw": vp[2], "score": (120.0 - pc) if exact else ((self.belief_verify_base + self._belief_bonus(lb["x"], lb["y"]) - pc) if self.belief_commit and self.policy == "belief" else
                                                           60.0 - pc - 1.5 * self.hint_w * self.hint_distance(hint, lb["x"], lb["y"])),
                                    "key": key, "note": "verify label L%d" % lb["id"]})
                break
        # doors whose plate is not read yet
        for dr in (reg.get("doors", []) if self.visit_doors else []):
            key = ("door", dr["id"])
            if dr.get("label") or key in self.visited_views or dr["n"] < 3 or (self._looked(gm, dr["x"], dr["y"]) and not (self.item is not None and self.item.get("key") == key)):
                continue
            if self.door_wall_max > 0:   # a door floating in free / unknown space is a false detection (glass, reflections)
                rr, cc = gm.to_cell(dr["x"], dr["y"])
                if not gm.inside(rr, cc) or gm.clear[rr, cc] > self.door_wall_max:
                    continue
            vp = self.viewpoint(gm, dr["x"], dr["y"], dr.get("nrm"), rp)
            if not vp or self.is_blocked(vp[0], vp[1]):
                continue
            pc = path_cost(vp[0], vp[1])
            if pc is None or pc > 40 or not on_way(vp[0], vp[1], pc):
                continue
            hd = self.hint_distance(hint, dr["x"], dr["y"])
            score = (0.0 if (self.belief_commit and self.policy == "belief") else self.door_bonus) - pc - self.hint_w * hd * (2.5 if hint and hint[0] == "point" else 2.0) \
                - self.number_penalty(known, dr["x"], dr["y"]) + self._belief_bonus(dr["x"], dr["y"]) + self.trend_bonus(trend, rp, dr["x"], dr["y"]) - self._route_penalty(dr["x"], dr["y"])
            out.append({"kind": "door", "id": dr["id"], "xy": vp[:2], "yaw": vp[2] if self.door_face else None, "obj": (dr["x"], dr["y"]), "score": score, "key": key,
                        "note": "read door D%d" % dr["id"]})
        # relook (see __init__): the last VLM goals ignored as looked at (within 5 min), once each, below every ordinary candidate
        for gx, gy, gt in (self._ignored_goals if self.relook else []):
            key = ("relook", int(round(gx)), int(round(gy)))
            if key in self.visited_views or time.time() - gt > 300.0:
                continue
            near = gm.nearest_trav(gx, gy, 3.0)
            if near is None:
                continue
            vx, vy = gm.to_xy(*near)
            pc = path_cost(vx, vy)
            if pc is None or self.is_blocked(vx, vy):
                continue
            out.append({"kind": "verify", "id": -1, "xy": (vx, vy), "yaw": None, "obj": (gx, gy), "score": -60.0 - pc, "key": key,
                        "note": "relook at VLM goal (%.0f, %.0f)" % (gx, gy)})
        # frontiers
        for cells in gm.frontiers(on_free=self.frontier_on_free):
            best = None
            for r, c in cells[:: max(1, len(cells) // 40)]:
                if self.frontier_min_dist > 0 and math.hypot(*(np.subtract(gm.to_xy(r, c), rp[:2]))) < self.frontier_min_dist:
                    continue
                if np.isfinite(costs[r, c]) and (best is None or costs[r, c] < best[0]):
                    best = (float(costs[r, c]), r, c)
            if best is None:
                continue
            x, y = gm.to_xy(best[1], best[2])
            self._fr_vis.append((float(x), float(y), len(cells)))
            if self.is_blocked(x, y) or math.hypot(x - rp[0], y - rp[1]) < 0.8:
                continue
            pc = best[0] * gm.res
            hd = self.hint_distance(hint, x, y)
            # unread signs / doors score far above any frontier: without this the robot keeps visiting lobby false positives
            # instead of exploring along the hint (e.g. into the corridor the LLM says the target is in)
            fb = self.frontier_hint_bonus if (self.frontier_hint_bonus > 0 and hint is not None
                                              and hd < self.hint_distance(hint, rp[0], rp[1]) - 3.0) else 0.0
            out.append({"kind": "frontier", "id": -1, "xy": (x, y), "yaw": None, "score": -pc - self.hint_w * hd * 1.8 - self.number_penalty(known, x, y) + self._belief_bonus(x, y) + fb + self.frontier_bonus + self.trend_bonus(trend, rp, x, y) + self._agree_bonus(rp, x, y) - self._route_penalty(x, y),
                        "key": None, "note": "frontier size %d" % len(cells)})
        if self.belief_peak and self.policy == "belief" and self.belief is not None and self.belief.matches((gm.h, gm.w), gm.x0, gm.y0, gm.res):
            Z = np.where(np.isfinite(costs) & (self.belief.looked == 0), self.belief.combined(), 0.0)
            if float(Z.max()) > 1e-6:
                r, c = np.unravel_index(int(np.argmax(Z)), Z.shape)
                x, y = gm.to_xy(r, c)
                if not self.is_blocked(x, y) and math.hypot(x - rp[0], y - rp[1]) >= 1.5:
                    out.append({"kind": "frontier", "id": -1, "xy": (x, y), "yaw": None, "key": None, "note": "belief peak",
                                "score": self.belief_w * self.belief.score(x, y) - float(costs[r, c]) * gm.res + self.frontier_bonus + self._agree_bonus(rp, x, y) - self._route_penalty(x, y)})
        if self.sign_neg_exclude and self.sign_neg_penalty > 0:
            out = [c for c in out if self._route_penalty(c["obj"][0] if c.get("obj") else c["xy"][0], c["obj"][1] if c.get("obj") else c["xy"][1]) <= 0]
        return out

    # ------------------------------------------------------------------ control loop
    def _tick(self):
        rp = self.robot_xy()
        if rp is None or self.gmap is None or self.reg is None:
            return
        if self.result is not None:
            return
        if self.det_reach_m > 0:
            self.reg = self._reach_filter(self.reg)
        elapsed = time.time() - self.t0
        if self.last_xy is not None:
            self.path_len += math.hypot(rp[0] - self.last_xy[0], rp[1] - self.last_xy[1])
        self.last_xy = rp

        lb = self.target_label()
        if lb is not None:
            d = math.hypot(lb["x"] - rp[0], lb["y"] - rp[1])
            if d <= self.arrive:
                self._finish(True, lb, elapsed)
                return
        if elapsed > self.max_time:
            self._finish(False, None, elapsed)
            return

        gm = self.gmap
        if self.policy == "belief":
            self._belief_tick(gm, rp)
        planned = gm.planner(rp[0], rp[1], self.escape_m)
        if planned is None:
            self.say("robot not on a traversable cell; waiting")
            return
        if getattr(gm, "escaped", False) and time.time() - getattr(self, "_escape_said", 0.0) > 20.0:
            self._escape_said = time.time()
            r_, c_ = planned[0]
            self.say("robot in a pocket of the traversable map at (%.1f, %.1f): planning from (%.1f, %.1f)" % ((rp[0], rp[1]) + gm.to_xy(r_, c_)))
        start, mcp, costs = planned

        # progress / stuck detection on the current item
        if self.stuck_per_item:
            sig = None if self.item is None else (self.item["kind"], self.item["xy"])
            if sig is None or self._prog_item is None or sig[0] != self._prog_item[0] or \
                    math.hypot(sig[1][0] - self._prog_item[1][0], sig[1][1] - self._prog_item[1][1]) > 1.0:
                self.progress = []
            self._prog_item = sig
        self.progress.append((time.time(), rp[0], rp[1]))
        if self.pass_seen_s > 0 and self.view_obj_dist > 0 and self.reg:
            now = time.time(); dt = 0.0 if self._near_t is None else min(now - self._near_t, 1.0); self._near_t = now
            for kind, lst in (("sign", self.reg.get("signs", [])), ("door", self.reg.get("doors", []))):
                for o in lst:
                    if math.hypot(o["x"] - rp[0], o["y"] - rp[1]) < self.view_obj_dist and (
                            self.view_half_fov <= 0 or abs((math.atan2(o["y"] - rp[1], o["x"] - rp[0]) - rp[2] + math.pi) % (2 * math.pi) - math.pi) <= self.view_half_fov):
                        k = (kind, o["id"])
                        self._near[k] = self._near.get(k, 0.0) + dt
                        if self._near[k] >= self.pass_seen_s:
                            if kind == "sign":
                                self._pass_signs.add(o["id"])   # the revisit key holds reads // 3, which moves on while it is still being read
                            else:
                                self.visited_views.add(("door", o["id"]))
        if not self._trail or math.hypot(rp[0] - self._trail[-1][0], rp[1] - self._trail[-1][1]) > 0.5:
            self._trail.append((rp[0], rp[1]))
            self._trail = self._trail[-40:]
        self.progress = [p for p in self.progress if time.time() - p[0] < self.stuck_s + 5.0]
        stuck = (len(self.progress) > 10 and time.time() - self.progress[0][0] > self.stuck_s
                 and math.hypot(rp[0] - self.progress[0][1], rp[1] - self.progress[0][2]) < 0.35 and self.item is not None)

        if lb is not None:
            vp = self.viewpoint(gm, lb["x"], lb["y"], None, rp, dists=(1.6, 1.3, 2.0, 2.4))
            item = {"kind": "target", "id": lb["id"], "xy": vp[:2] if vp else (lb["x"], lb["y"]),
                    "yaw": vp[2] if vp else None, "score": 1e9, "key": None, "note": "go to room %s" % self.target}
            if self.item is None or self.item["kind"] != "target":
                self.say("target %s located at (%.1f, %.1f); approaching" % (self.target, lb["x"], lb["y"]))
            self.item, self.item_t = item, time.time()
        else:
            reeval = (self.item is None or time.time() - self.item_t > 8.0 or stuck or self._item_done(rp))
            if stuck and self.item is not None:
                self.say("stuck near (%.1f, %.1f) going to %s; blocking it" % (rp[0], rp[1], self.item["note"]))
                x, y = self.item["xy"]
                self.blocked.append((x, y, time.time() + (self.frontier_block_s if self.item["kind"] == "frontier" else 150.0)))
                if self.item["key"]:
                    self.visited_views.add(self.item["key"])
                self.progress = []
                self.item = None; reeval = True
            if reeval:
                cands = self.candidates(gm, (start, mcp, costs), rp)
                self._top = [(c["note"], round(c["score"], 1)) for c in sorted(cands, key=lambda c: -c["score"])[:4]]
                if cands:
                    self._empty_t = None
                else:
                    # give up only after 30 s without any candidate: a person standing in the only corridor removes every
                    # candidate behind them for a few seconds (the old test timed 30 s from the last item choice)
                    self._empty_t = self._empty_t or time.time()
                    if time.time() - self._empty_t > 30 and time.time() - self.t0 > 300:
                        left = len(gm.frontiers(on_free=self.frontier_on_free)) if self.keep_trying else 0
                        if left:
                            # 11-11 T111 gave up here with the corridor holding the target unexplored: free the blocked goals, try again
                            self.say("no reachable candidate, %d frontiers left: freeing %d blocked goals and trying again" % (left, len(self.blocked)))
                            self.blocked, self._empty_t = [], None
                            return
                        self.say("no candidates left (map fully explored?)")
                        self._finish(False, None, elapsed)
                    return
                if self.backtrack_penalty > 0 and len(self._trail) > 4:
                    tx, ty = self._trail[max(0, len(self._trail) - 12)]   # ~6 m of recent travel
                    hx, hy = rp[0] - tx, rp[1] - ty
                    hn = math.hypot(hx, hy)
                    if hn > 2.0:
                        for c in cands:
                            vx, vy = c["xy"][0] - rp[0], c["xy"][1] - rp[1]
                            vn = math.hypot(vx, vy)
                            if c["kind"] != "target" and vn > 3.0 and (vx * hx + vy * hy) / (vn * hn) < -0.3:
                                c["score"] -= self.backtrack_penalty
                best = max(cands, key=lambda c: c["score"])
                if self.item is not None:   # hysteresis: keep the current goal unless another is clearly better
                    cur = next((c for c in cands if c["kind"] == self.item["kind"] and (
                        (c["key"] is not None and c["key"] == self.item["key"]) or
                        (c["key"] is None and math.hypot(c["xy"][0] - self.item["xy"][0], c["xy"][1] - self.item["xy"][1]) < (self.frontier_match_m if c["kind"] == "frontier" else 3.0)))), None)
                    if cur is not None and best["score"] < cur["score"] + 8.0:
                        best = cur
                    if cur is not None:
                        self._hold_t = None
                    elif (self.frontier_hold_s > 0 and self.item["kind"] == "frontier" and best["score"] < -15.0
                          and math.hypot(self.item["xy"][0] - rp[0], self.item["xy"][1] - rp[1]) > 1.5):
                        self._hold_t = self._hold_t or time.time()
                        if time.time() - self._hold_t < self.frontier_hold_s:
                            best = dict(self.item)     # the frontier flickered away: do not turn around for a far, bad goal yet
                        else:
                            self._hold_t = None
                    else:
                        self._hold_t = None
                self._dump_decision(gm, cands, best, rp)
                if self.item is None or best["kind"] != self.item["kind"] or \
                        math.hypot(best["xy"][0] - self.item["xy"][0], best["xy"][1] - self.item["xy"][1]) > 1.0:
                    hint = self.hint()
                    self.say("-> %s at (%.1f, %.1f) score %.1f [hint=%s, %d candidates]" % (
                        best["note"], best["xy"][0], best["xy"][1], best["score"],
                        None if hint is None else hint[0], len(cands)))
                self.item, self.item_t = best, time.time()
        if self.look_stop_s > 0 and lb is None and self._look_stop(rp):
            self._hold(rp)
        else:
            self._drive(gm, mcp, costs, start, rp)
        self._landmarks()
        self._publish_status(elapsed, rp)

    def _look_stop(self, rp):
        """True while standing still for an unread door (no plate), label (number not confirmed) or sign (no entries) within
        look_stop_m that a camera sees (not behind); once per object, not again within 2 m / 2 s of the last stop"""
        now = time.time()
        if self._stop is not None:
            (kind, oid), until = self._stop
            if now < until and not self._stop_read(kind, oid):
                return True
            self._stop, self._stop_after, self._stop_xy = None, now + 2.0, (rp[0], rp[1])
            return False
        if now < self._stop_after or self.item is None:
            return False
        if self._stop_xy is not None and math.hypot(rp[0] - self._stop_xy[0], rp[1] - self._stop_xy[1]) < 2.0:
            return False
        reg = self.reg or {}
        objs = [("door", o) for o in reg.get("doors", []) if not o.get("label") and o.get("n", 0) >= 3 and o.get("conf", 0) >= 0.5] + \
               [("label", o) for o in reg.get("labels", []) if not o.get("number")] + \
               [("sign", o) for o in reg.get("signs", []) if not o.get("cues") and not o.get("dead") and o.get("valid", True) and o.get("reads", 0) < 3]
        best = None
        for kind, o in objs:
            if (kind, o["id"]) in self._stopped:
                continue
            d = math.hypot(o["x"] - rp[0], o["y"] - rp[1])
            if d > self.look_stop_m:
                continue
            if len(rp) > 2 and abs((math.atan2(o["y"] - rp[1], o["x"] - rp[0]) - rp[2] + math.pi) % (2 * math.pi) - math.pi) > math.radians(120):
                continue
            if best is None or d < best[0]:
                best = (d, kind, o["id"])
        if best is None:
            return False
        self._stopped.add(best[1:])
        self._stop = (best[1:], now + self.look_stop_s)
        self.say("look stop: %s %d at %.1f m" % (best[1], best[2], best[0]))
        return True

    def _stop_read(self, kind, oid):
        for o in (self.reg or {}).get({"door": "doors", "label": "labels", "sign": "signs"}[kind], []):
            if o["id"] == oid:
                return bool(o.get("label") if kind == "door" else o.get("number") if kind == "label" else o.get("cues"))
        return False

    def _hold(self, rp):
        """stand still: the goal is the robot's own position"""
        m = PoseStamped()
        m.header.frame_id = "map"; m.header.stamp = self.get_clock().now().to_msg()
        m.pose.position.x, m.pose.position.y = float(rp[0]), float(rp[1])
        yaw = rp[2] if len(rp) > 2 else 0.0
        m.pose.orientation.z, m.pose.orientation.w = math.sin(yaw / 2), math.cos(yaw / 2)
        self.pub_goal.publish(m)

    def _item_done(self, rp):
        it = self.item
        if it is None:
            return True
        d = math.hypot(it["xy"][0] - rp[0], it["xy"][1] - rp[1])
        near = d < 0.9
        dwell = 4.0
        if self.view_obj_dist > 0 and it.get("obj") is not None:
            near = near or math.hypot(it["obj"][0] - rp[0], it["obj"][1] - rp[1]) < self.view_obj_dist   # standing on the viewpoint always counts (it can be >2 m from the object)
            dwell = self.view_dwell
        if it.get("key") == ("scan", 0):
            dwell = 7.0      # turning round takes ~3 s, then each camera needs a detection cycle
        if it.get("key") and it["key"][0] == "relook":
            dwell = 3.0      # a few OCR frames per camera
        if it["kind"] in ("door", "sign", "verify") and near:
            # give perception a moment at the viewpoint, then mark it visited
            if it.setdefault("arrived", time.time()) and time.time() - it["arrived"] > dwell:
                self.visited_views.add(it["key"])
                return True
            return False
        return d < 0.7 if it["kind"] == "frontier" else False

    def _drive(self, gm, mcp, costs, start, rp):
        it = self.item
        if it is None:
            return
        gx, gy = it["xy"]
        r, c = gm.to_cell(gx, gy)
        if not gm.inside(r, c):
            return
        if not np.isfinite(costs[r, c]):
            near = gm.nearest_trav(gx, gy, 1.0)
            if (near is None or not np.isfinite(costs[near])) and it["kind"] == "target":
                # T102: the plate's viewpoint was not traversable and nothing within 1 m was reachable, so the target item was
                # dropped and re-made every tick ('approaching' for 800 s, 3.5 m from the plate): go to the nearest reachable cell
                n = int(3.0 / gm.res)
                rr, cc = np.mgrid[max(0, r - n):min(gm.h, r + n + 1), max(0, c - n):min(gm.w, c + n + 1)]
                ok = np.isfinite(costs[rr, cc])
                if ok.any():
                    d2 = np.where(ok, (rr - r) ** 2 + (cc - c) ** 2, np.inf)
                    k = np.unravel_index(int(np.argmin(d2)), d2.shape)
                    near = (int(rr[k]), int(cc[k]))
            if near is None or not np.isfinite(costs[near]):
                self.blocked.append((gx, gy, time.time() + 90.0))
                self.item = None
                return
            r, c = near
        try:
            path = np.array(mcp.traceback((r, c)))     # robot -> goal
        except Exception as e:  # noqa: BLE001
            self.say("no path to %s: %r" % (it["note"], e))
            self.blocked.append((gx, gy, time.time() + 60.0))
            self.item = None
            return
        arc = np.concatenate([[0], np.cumsum(np.linalg.norm(np.diff(path, axis=0), axis=1))]) * gm.res if len(path) > 1 else np.zeros(1)
        k = int(np.searchsorted(arc, self.lookahead))
        k = min(k, len(path) - 1)
        cx, cy = gm.to_xy(*path[k])
        final = k >= len(path) - 1
        msg = PoseStamped()
        msg.header.frame_id = "map"; msg.header.stamp = self.get_clock().now().to_msg()
        msg.pose.position.x, msg.pose.position.y = float(cx), float(cy)
        yaw = it["yaw"] if (final and it.get("yaw") is not None) else math.atan2(cy - rp[1], cx - rp[0])
        msg.pose.orientation.z, msg.pose.orientation.w = math.sin(yaw / 2), math.cos(yaw / 2)
        (self.pub_goal_yaw if final and it.get("yaw") is not None else self.pub_goal).publish(msg)
        self._markers(gm, path, (cx, cy), it)

    # ------------------------------------------------------------------ output
    def _finish(self, success, lb, elapsed):
        rp0 = self.robot_xy()
        self.result = {"target": self.target, "found": bool(success), "elapsed_s": round(elapsed, 1),
                       "robot_xy": None if rp0 is None else [round(rp0[0], 2), round(rp0[1], 2)],
                       "path_len_m": round(self.path_len, 1), "label_xy": None if lb is None else [round(lb["x"], 2), round(lb["y"], 2)],
                       "n_labels": len((self.reg or {}).get("labels", [])), "n_doors": len((self.reg or {}).get("doors", [])),
                       "signs": [{"id": s["id"], "xy": [round(s["x"], 1), round(s["y"], 1)], "cues": s["cues"]}
                                 for s in (self.reg or {}).get("signs", [])],
                       "stats": (self.reg or {}).get("stats")}
        with open(self.out_dir + "/result.json.tmp", "w") as fh:
            json.dump(self.result, fh, indent=1)
        os.replace(self.out_dir + "/result.json.tmp", self.out_dir + "/result.json")
        self.say("%s room %s after %.0f s, %.0f m" % ("FOUND" if success else "GAVE UP on", self.target, elapsed, self.path_len))
        self.pub_status.publish(String(data=json.dumps({"state": "DONE", **self.result})))
        # stop: hold position by pointing the goal at the robot
        rp = self.robot_xy()
        if rp:
            m = PoseStamped(); m.header.frame_id = "map"
            m.pose.position.x, m.pose.position.y, m.pose.orientation.w = rp[0], rp[1], 1.0
            self.pub_goal.publish(m)
        if self.exit_when_done:
            raise SystemExit(0)

    def _publish_status(self, elapsed, rp):
        st = {"state": self.state, "target": self.target, "elapsed": round(elapsed), "path_len": round(self.path_len, 1),
              "item": None if self.item is None else self.item["note"], "pose": [round(rp[0], 2), round(rp[1], 2)],
              "yaw": round(rp[2], 2) if len(rp) > 2 else 0.0, "hint": self._hint_text(), "cands": self._top, "log": self._say_log,
              "belief": ({k: v for k, v in self.belief_info.items() if k != "t"} if self.belief_info else None)}
        if self.belief is not None and time.time() - self._looked_pub_t > 2.0:   # drawn by the gateway's map viewer (:8081)
            self._looked_pub_t = time.time()
            b = self.belief
            st["looked"] = {"x0": round(float(b.x0), 3), "y0": round(float(b.y0), 3), "res": float(b.res), "w": int(b.looked.shape[1]),
                            "h": int(b.looked.shape[0]), "z": base64.b64encode(zlib.compress(np.packbits(b.looked > 0).tobytes(), 6)).decode()}
        self.pub_status.publish(String(data=json.dumps(st)))

    def _landmarks(self):
        """Landmark map for RViz: read plates (green = accepted number, grey = unconfirmed), doors, signs with their
        cue arrows (red when the cue's range holds the target) and the frontiers the finder considers."""
        if time.time() - self._lm_t < 1.0 or not self.reg:
            return
        self._lm_t = time.time()
        ma = MarkerArray()
        wipe = Marker(); wipe.header.frame_id = "map"; wipe.action = Marker.DELETEALL
        ma.markers.append(wipe)
        n = [0]

        def mk(ns, typ, x, y, z, scale, rgba, text=None, pts=None):
            m = Marker(); m.header.frame_id = "map"; m.ns = ns; m.id = n[0]; n[0] += 1; m.type = typ; m.action = Marker.ADD
            m.pose.position.x, m.pose.position.y, m.pose.position.z = float(x), float(y), float(z)
            m.pose.orientation.w = 1.0
            m.scale.x, m.scale.y, m.scale.z = scale
            m.color = ColorRGBA(r=rgba[0], g=rgba[1], b=rgba[2], a=rgba[3])
            if text is not None:
                m.text = text
            if pts is not None:
                m.points = [Point(x=float(a), y=float(b), z=float(c)) for a, b, c in pts]
            ma.markers.append(m)

        for d in self.reg.get("doors", []):
            ok = bool(d.get("label"))
            mk("doors", Marker.CUBE, d["x"], d["y"], 1.0, (0.15, 0.7, 2.0), (0.2, 0.8, 0.3, 0.5) if ok else (0.6, 0.6, 0.6, 0.35))
        for lb in self.reg.get("labels", []):
            num = lb.get("number")
            if num:
                hit = num == self.target
                col = (1.0, 0.85, 0.0, 1.0) if hit else (0.2, 1.0, 0.3, 1.0)
                mk("labels", Marker.TEXT_VIEW_FACING, lb["x"], lb["y"], 2.1, (0.0, 0.0, 0.55 if hit else 0.4), col, text=num)
            else:
                reads = [a for a, _ in lb["reads"]]
                guess = max(set(reads), key=reads.count) if reads else "?"
                mk("labels", Marker.TEXT_VIEW_FACING, lb["x"], lb["y"], 2.1, (0.0, 0.0, 0.3), (0.7, 0.7, 0.7, 0.9), text=guess + "?")
            mk("labels", Marker.SPHERE, lb["x"], lb["y"], 1.6, (0.2, 0.2, 0.2), (0.2, 1.0, 0.3, 1.0) if num else (0.7, 0.7, 0.7, 1.0))
        for s in self.reg.get("signs", []):
            col = (0.4, 0.4, 0.4, 0.6) if s.get("dead") else (1.0, 0.55, 0.0, 1.0)
            mk("signs", Marker.CYLINDER, s["x"], s["y"], 1.2, (0.3, 0.3, 0.6), col)
            mk("signs", Marker.TEXT_VIEW_FACING, s["x"], s["y"], 2.1, (0.0, 0.0, 0.3), col, text="S%d" % s["id"])
            for c in s.get("cues", []):
                b = c.get("bearing")
                if b is None:
                    continue
                hit = self._cue_hit(c)
                rgba = (1.0, 0.1, 0.1, 1.0) if hit else (0.8, 0.8, 0.2, 0.45)
                ln = 3.5 if hit else 1.6
                mk("cues", Marker.ARROW, 0, 0, 0, (0.08, 0.2, 0.2), rgba,
                   pts=[(s["x"], s["y"], 1.2), (s["x"] + ln * math.cos(b), s["y"] + ln * math.sin(b), 1.2)])
                if hit:
                    mk("cues", Marker.TEXT_VIEW_FACING, s["x"] + (ln + 0.4) * math.cos(b), s["y"] + (ln + 0.4) * math.sin(b), 1.4,
                       (0.0, 0.0, 0.3), rgba, text=c["place"])
        for x, y, size in self._fr_vis:
            mk("frontiers", Marker.SPHERE, x, y, 0.2, (0.3, 0.3, 0.3), (0.2, 0.5, 1.0, 0.9))
        self.pub_landmarks.publish(ma)
        if self.belief is not None and self.gmap is not None:
            g = OccupancyGrid(); g.header.frame_id = "map"; g.header.stamp = self.get_clock().now().to_msg()
            g.info.resolution, g.info.width, g.info.height = float(self.belief.res), int(self.belief.shape[1]), int(self.belief.shape[0])
            g.info.origin.position.x, g.info.origin.position.y, g.info.origin.orientation.w = float(self.belief.x0), float(self.belief.y0), 1.0
            g.data = self.belief.as_occupancy().flatten().tolist()
            self.pub_belief.publish(g)

    def _markers(self, gm, path, carrot, it):
        ma = MarkerArray()
        line = Marker(); line.header.frame_id = "map"; line.ns = "path"; line.id = 0; line.type = Marker.LINE_STRIP
        line.action = Marker.ADD; line.scale.x = 0.05; line.color = ColorRGBA(r=0.1, g=0.8, b=1.0, a=1.0)
        for r, c in path[::3]:
            x, y = gm.to_xy(r, c); line.points.append(Point(x=float(x), y=float(y), z=0.1))
        ma.markers.append(line)
        goal = Marker(); goal.header.frame_id = "map"; goal.ns = "goal"; goal.id = 1; goal.type = Marker.SPHERE
        goal.action = Marker.ADD; goal.scale.x = goal.scale.y = goal.scale.z = 0.4
        goal.pose.position.x, goal.pose.position.y, goal.pose.position.z = float(it["xy"][0]), float(it["xy"][1]), 0.3
        goal.pose.orientation.w = 1.0; goal.color = ColorRGBA(r=1.0, g=0.3, b=0.0, a=1.0)
        ma.markers.append(goal)
        self.pub_markers.publish(ma)


def main():
    rclpy.init()
    node = RoomFinder()
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
