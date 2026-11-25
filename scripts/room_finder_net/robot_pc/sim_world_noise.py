"""Simulation only: real-robot map conditions injected into robot_gateway.py (off unless SIM_NOISE=1).

  SIM_PEOPLE_EVERY=90     on average every this many seconds a "person" (0.45 m disk, 0-1.7 m tall in the cloud) stands
                          2.5-5 m ahead of the robot on free map cells, for SIM_PEOPLE_S=5 s (or a range a-b), then walks off
                          (the lidar stops seeing it; whatever the map kept is a ghost wall until rays clear it)
  SIM_WALL_GROW=0         occupied cells of the published map are dilated by this much (robot_gateway_real.py) (the sim corridors are 2.4 m wall to
                          wall, the real ones 1.8-2.0 m with doors, fire boxes and benches along the walls)
  SIM_NOISE_SEED=0
"""
import math
import os
import random
import time

import numpy as np

ON = os.environ.get("SIM_NOISE", "0") == "1"
_seed = int(float(os.environ.get("SIM_NOISE_SEED", "0"))) or int(time.time() * 1000) % 2 ** 31
RNG = random.Random(_seed + 1)
EVERY = float(os.environ.get("SIM_PEOPLE_EVERY", "90"))
DUR = tuple(float(v) for v in os.environ.get("SIM_PEOPLE_S", "5").split("-"))
DUR = DUR * 2 if len(DUR) == 1 else DUR
GROW = float(os.environ.get("SIM_WALL_GROW", "0"))


class People:
    def __init__(self):
        self.person = None          # (x, y, t_end)
        self.next_t = time.time() + RNG.expovariate(1.0 / EVERY) if EVERY > 0 else float("inf")
        self.count = 0
        self.history = []           # (x, y, t_end, t_start) of every person so far

    def points(self, pose, yaw, free_at):
        """world points of the current person (empty array when none); free_at(x, y) -> True if the map cell is free"""
        now = time.time()
        if self.person and now > self.person[2]:
            self.person = None
            self.next_t = now + RNG.expovariate(1.0 / EVERY)
        if self.person is None and now >= self.next_t:
            for _ in range(20):
                d, a = RNG.uniform(2.5, 5.0), yaw + RNG.uniform(-0.4, 0.4)
                x, y = pose[0] + d * math.cos(a), pose[1] + d * math.sin(a)
                if free_at(x, y):
                    self.person = (x, y, now + RNG.uniform(*DUR))
                    self.count += 1
                    self.history.append(self.person + (now,))   # + when they started standing
                    print("sim_world_noise: person #%d at (%.1f, %.1f) for %.0f s" % (self.count, x, y, self.person[2] - now), flush=True)
                    break
            else:
                self.next_t = now + 5.0
        if self.person is None:
            return np.zeros((0, 3), np.float32)
        x, y, _ = self.person
        ang = np.linspace(0, 2 * math.pi, 24, endpoint=False)
        z = np.linspace(0.0, 1.7, 8)
        px = (x + 0.22 * np.cos(ang))[:, None].repeat(len(z), 1).ravel()
        py = (y + 0.22 * np.sin(ang))[:, None].repeat(len(z), 1).ravel()
        pz = np.tile(z, len(ang)) + pose[2] - 0.5
        return np.stack([px, py, pz], 1).astype(np.float32)

