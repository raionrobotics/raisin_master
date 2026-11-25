"""Geometry of the simulated three-camera OAK-D Pro W mast (see raisin_raibo2 modules/oak_mast)."""
import math

import numpy as np

CAMERAS = ("oak_front", "oak_left", "oak_right")
HFOV = 1.885                      # rad, colour and depth share it
COLOR_W, COLOR_H = 3840, 2880
DEPTH_W, DEPTH_H = 640, 480
FX = (COLOR_W / 2.0) / math.tan(HFOV / 2.0)
CX, CY = COLOR_W / 2.0, COLOR_H / 2.0
DEPTH_SCALE = COLOR_W / DEPTH_W   # colour px per depth px


def pixel_to_body(u, v, z):
    """Colour pixel + z-depth (m) -> point in the camera body frame (x forward, y left, z up).

    The image is optical (x right, y down, z forward); ROS body frames used for TF are x forward, y left, z up.
    Accepts scalars or arrays.
    """
    xo = (np.asarray(u, dtype=np.float64) - CX) / FX * z
    yo = (np.asarray(v, dtype=np.float64) - CY) / FX * z
    return np.stack([np.asarray(z, dtype=np.float64) * np.ones_like(xo), -xo, -yo], axis=-1)


def body_to_pixel(p):
    """Camera-body point(s) (N,3) -> colour pixel (u, v) and z-depth; z <= 0 means behind the camera."""
    p = np.atleast_2d(p)
    z = p[:, 0]
    with np.errstate(divide="ignore", invalid="ignore"):
        u = CX + FX * (-p[:, 1]) / z
        v = CY + FX * (-p[:, 2]) / z
    return u, v, z


def depth_at_color(depth, u0, v0, u1, v1):
    """Valid depth samples (m) inside a colour-resolution box, from the half-resolution depth image."""
    x0, x1 = int(max(0, u0 / DEPTH_SCALE)), int(min(DEPTH_W, u1 / DEPTH_SCALE + 1))
    y0, y1 = int(max(0, v0 / DEPTH_SCALE)), int(min(DEPTH_H, v1 / DEPTH_SCALE + 1))
    if x1 <= x0 or y1 <= y0:
        return np.empty(0)
    d = depth[y0:y1, x0:x1].reshape(-1)
    return d[np.isfinite(d) & (d > 0.15)]


def quat_to_rot(q):
    x, y, z, w = q
    return np.array([
        [1 - 2 * (y * y + z * z), 2 * (x * y - z * w), 2 * (x * z + y * w)],
        [2 * (x * y + z * w), 1 - 2 * (x * x + z * z), 2 * (y * z - x * w)],
        [2 * (x * z - y * w), 2 * (y * z + x * w), 1 - 2 * (x * x + y * y)]])
