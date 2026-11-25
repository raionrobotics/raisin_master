"""
Borrowed from https://github.com/naokiyokoyama/frontier_exploration
"""
import os
from typing import List, Optional

import cv2
import numpy as np
try:
    from numba import njit
except ImportError:
    # numba is optional: it only JIT-accelerates two helpers. Fall back to a
    # no-op decorator so frontier detection runs (in pure Python) without it.
    def njit(*args, **kwargs):
        if len(args) == 1 and callable(args[0]) and not kwargs:
            return args[0]
        def _wrap(func):
            return func
        return _wrap

from mm_dev.frontier_detection.bresenham_line import bresenhamline
from mm_dev.frontier_detection.frontier_utils import closest_line_segment
from mm_dev.common.costmap_2d import PyCostmap2D
from mm_dev.common.tf_utils import transform_msg_to_xyyaw
from nav_msgs.msg import OccupancyGrid
from geometry_msgs.msg import Transform

VISUALIZE = os.environ.get("MAP_VISUALIZE", "False").lower() == "true"
DEBUG = os.environ.get("MAP_DEBUG", "False").lower() == "true"


def detect_frontier_waypoints(
    full_map: np.ndarray,
    explored_mask: np.ndarray,
    area_thresh: Optional[int] = -1,
    xy: Optional[np.ndarray] = None,
):
    if DEBUG:
        import time

        os.makedirs("map_debug", exist_ok=True)
        cv2.imwrite(
            f"map_debug/{int(time.time())}_debug_full_map_{area_thresh}.png", full_map
        )
        cv2.imwrite(
            f"map_debug/{int(time.time())}_debug_explored_mask_{area_thresh}.png",
            explored_mask,
        )

    if VISUALIZE:
        img = cv2.cvtColor(full_map * 255, cv2.COLOR_GRAY2BGR)
        img[explored_mask > 0] = (127, 127, 127)

        cv2.imshow("inputs", img)
        cv2.waitKey(0)
        cv2.destroyAllWindows()

    explored_mask[full_map == 0] = 0
    frontiers = detect_frontiers(full_map, explored_mask, area_thresh)
    if VISUALIZE:
        img = cv2.cvtColor(full_map * 255, cv2.COLOR_GRAY2BGR)
        img[explored_mask > 0] = (127, 127, 127)
        # Draw a dot at each point on each frontier
        for idx, frontier in enumerate(frontiers):
            # Uniformly sample colors from the COLORMAP_RAINBOW
            color = cv2.applyColorMap(
                np.uint8([255 * (idx + 1) / len(frontiers)]), cv2.COLORMAP_RAINBOW
            )[0][0]
            color = tuple(int(i) for i in color)
            for idx2, p in enumerate(frontier):
                if idx2 < len(frontier) - 1:
                    cv2.line(img, p[0], frontier[idx2 + 1][0], color, 3)
        cv2.imshow("frontiers", img)
        cv2.waitKey(0)
        cv2.destroyAllWindows()

    waypoints = frontier_waypoints(frontiers, xy)
    return waypoints


def detect_frontiers(
    full_map: np.ndarray, explored_mask: np.ndarray, area_thresh: Optional[int] = -1
) -> List[np.ndarray]:
    """Detects frontiers in a map.

    Args:
        full_map (np.ndarray): White polygon on black image, where white is navigable.
        Mono-channel mask.
        explored_mask (np.ndarray): Portion of white polygon that has been seen already.
        This is also a mono-channel mask.
        area_thresh (int, optional): Minimum unexplored area (in pixels) needed adjacent
        to a frontier for that frontier to be valid. Defaults to -1.

    Returns:
        np.ndarray: A mono-channel mask where white contours represent each frontier.
    """
    # Find the contour of the explored area
    filtered_explored_mask = filter_out_small_unexplored(
        full_map, explored_mask, area_thresh
    )
    contours, _ = cv2.findContours(
        filtered_explored_mask, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE
    )
    if VISUALIZE:
        img = cv2.cvtColor(full_map * 255, cv2.COLOR_GRAY2BGR)
        img[explored_mask > 0] = (127, 127, 127)
        cv2.drawContours(img, contours, -1, (0, 255, 0), 3)
        cv2.imshow("contours", img)
        cv2.waitKey(0)
        cv2.destroyAllWindows()
    unexplored_mask = np.where(filtered_explored_mask > 0, 0, full_map)
    unexplored_mask = cv2.blur(  # blurring for some leeway
        np.where(unexplored_mask > 0, 255, unexplored_mask), (3, 3)
    )
    frontiers = []
    # TODO: There shouldn't be more than one contour (only one explored area on map)
    for contour in contours:
        frontiers.extend(
            contour_to_frontiers(interpolate_contour(contour), unexplored_mask)
        )
    return frontiers


def filter_out_small_unexplored(
    full_map: np.ndarray, explored_mask: np.ndarray, area_thresh: int
):
    """Edit the explored map to add small unexplored areas, which ignores their
    frontiers."""
    if area_thresh == -1:
        return explored_mask

    unexplored_mask = full_map.copy()
    unexplored_mask[explored_mask > 0] = 0

    if VISUALIZE:
        img = cv2.cvtColor(unexplored_mask * 255, cv2.COLOR_GRAY2BGR)
        cv2.imshow("unexplored mask", img)
        cv2.waitKey(0)
        cv2.destroyAllWindows()

    # Find contours in the unexplored mask
    contours, _ = cv2.findContours(
        unexplored_mask, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE
    )

    if VISUALIZE:
        img = cv2.cvtColor(unexplored_mask * 255, cv2.COLOR_GRAY2BGR)
        # Draw the contours in red
        cv2.drawContours(img, contours, -1, (0, 0, 255), 3)
        cv2.imshow("unexplored mask with contours", img)
        cv2.waitKey(0)
        cv2.destroyAllWindows()

    # Add small unexplored areas to the explored map
    small_contours = []
    for i, contour in enumerate(contours):
        if cv2.contourArea(contour) < area_thresh:
            mask = np.zeros_like(explored_mask)
            mask = cv2.drawContours(mask, [contour], 0, 1, -1)
            masked_values = unexplored_mask[mask.astype(bool)]
            values = set(masked_values.tolist())
            if 1 in values and len(values) == 1:
                small_contours.append(contour)
    new_explored_mask = explored_mask.copy()
    cv2.drawContours(new_explored_mask, small_contours, -1, 255, -1)

    if VISUALIZE and len(small_contours) > 0:
        # Draw the full map and the new explored mask, then outline the contours that
        # were added to the explored mask
        img = cv2.cvtColor(full_map * 255, cv2.COLOR_GRAY2BGR)
        img[new_explored_mask > 0] = (127, 127, 127)
        cv2.drawContours(img, small_contours, -1, (0, 0, 255), 3)
        cv2.imshow("small unexplored areas", img)
        cv2.waitKey(0)
        cv2.destroyAllWindows()

    return new_explored_mask


# nav2 cost values.
INSCRIBED_INFLATED_OBSTACLE = 253
LETHAL_OBSTACLE = 254
NO_INFORMATION = 255

# How far from unexplored ground a contour point may sit and still count as a
# frontier, in cells (the contour runs on a dilated map, so it is never exactly
# on the boundary).
UNKNOWN_REACH = int(os.environ.get('REASONNAV_FRONTIER_UNKNOWN_REACH', '3'))
# ...and how far it must stay from a wall.
WALL_CLEARANCE = int(os.environ.get('REASONNAV_FRONTIER_WALL_CLEARANCE', '2'))
# Shortest run of boundary cells that counts as a frontier. Measured on the
# contour, which sits 3 cells inside the walls -- so the crossing at the end of
# a corridor is its width minus ~0.8 m. At 8 cells a 1.5 m corridor produced
# nothing at all (its crossing came out at 6-7 cells); 5 keeps corridors down
# to ~1.3 m while still discarding the 3-cell stubs this exists to remove.
MIN_FRONTIER_CELLS = int(os.environ.get('REASONNAV_MIN_FRONTIER_CELLS', '5'))
# Narrowest wall-to-wall gap worth a frontier, in metres. Measured on the
# actual LETHAL cells: from the segment's midpoint, march across the segment
# (i.e. across the corridor) both ways until a wall, sum the two distances.
# The segment's own length is not the corridor width -- the contour it lies on
# is eroded 3 cells from the walls -- so a 0.8 m rig was being offered gaps it
# could not fit through, and denied gaps it could.
MIN_GAP_M = float(os.environ.get('REASONNAV_MIN_GAP_M', '1.5'))
GAP_PROBE_M = 3.0          # a side with no wall within this is simply "open"
# Window, in cells, searched for the unknown that sets a frontier's heading.
OUTWARD_LOOK = int(os.environ.get('REASONNAV_FRONTIER_OUTWARD_LOOK', '8'))


def interpolate_contour(contour):
    """Given a cv2 contour, this function will add points in between each pair of
    points in the contour using the bresenham algorithm to make the contour more
    continuous.
    :param contour: A cv2 contour of shape (N, 1, 2)
    :return:
    """
    # First, reshape and expand the frontier to be a 2D array of shape (N-1, 2, 2)
    # representing line segments between adjacent points
    line_segments = np.concatenate((contour[:-1], contour[1:]), axis=1).reshape(
        (-1, 2, 2)
    )
    # Also add a segment connecting the last point to the first point
    line_segments = np.concatenate(
        (line_segments, np.array([contour[-1], contour[0]]).reshape((1, 2, 2)))
    )
    pts = []
    for (x0, y0), (x1, y1) in line_segments:
        pts.append(
            bresenhamline(np.array([[x0, y0]]), np.array([[x1, y1]]), max_iter=-1)
        )
    pts = np.concatenate(pts).reshape((-1, 1, 2))
    return pts


@njit
def contour_to_frontiers(contour, unexplored_mask):
    """Given a contour from OpenCV, return a list of numpy arrays. Each array contains
    contiguous points forming a single frontier. The contour is assumed to be a set of
    contiguous points, but some of these points are not on any frontier, indicated by
    having a value of 0 in the unexplored mask. This function will split the contour
    into multiple arrays that exclude such points."""
    bad_inds = []
    num_contour_points = len(contour)
    for idx in range(num_contour_points):
        x, y = contour[idx][0]
        if unexplored_mask[y, x] == 0:
            bad_inds.append(idx)
    frontiers = np.split(contour, bad_inds)
    # np.split is fast but does NOT remove the element at the split index
    filtered_frontiers = []
    front_last_split = (
        0 not in bad_inds
        and len(bad_inds) > 0
        and max(bad_inds) < num_contour_points - 2
    )
    for idx, f in enumerate(frontiers):
        # The contour is interpolated to one point per cell, so this length is
        # in cells: at 0.10 m/cell the old ">2" accepted a 30 cm sliver of
        # boundary as somewhere worth walking to. A frontier has to be a gap the
        # rig could actually pass through to be worth a trip.
        if len(f) >= MIN_FRONTIER_CELLS or (idx == 0 and front_last_split):
            if idx == 0:
                filtered_frontiers.append(f)
            else:
                filtered_frontiers.append(f[1:])
    # Combine the first and last frontier if the first point of the first frontier and
    # the last point of the last frontier are the first and last points of the original
    # contour. Only check if there are at least 2 frontiers.
    if len(filtered_frontiers) > 1 and front_last_split:
        last_frontier = filtered_frontiers.pop()
        filtered_frontiers[0] = np.concatenate((last_frontier, filtered_frontiers[0]))
    # The first segment is let through above regardless of length, on the
    # assumption it will be joined to the last one. When there is nothing to
    # join it to, a one- or two-point stub reaches get_frontier_midpoint and
    # crashes on an empty cumulative length -- taking vlm_nav's main loop down
    # with it. Apply the length rule to the final list, not just the pieces.
    return [f for f in filtered_frontiers if len(f) >= max(2, MIN_FRONTIER_CELLS)]


def frontier_waypoints(
    frontiers: List[np.ndarray], xy: Optional[np.ndarray] = None
) -> np.ndarray:
    """For each given frontier, returns the point on the frontier closest (euclidean
    distance) to the given coordinate. If coordinate is not given, will just return
    the midpoints of each frontier.

    Args:
        frontiers (List[np.ndarray]): list of arrays of shape (X, 1, 2), where each
        array is a frontier and X is NOT the same across arrays
        xy (np.ndarray): the given coordinate

    Returns:
        np.ndarray: array of waypoints, one for each frontier
    """
    if xy is None:
        return np.array([get_frontier_midpoint(i) for i in frontiers])
    return np.array([get_closest_frontier_point(xy, i) for i in frontiers])


@njit
def get_frontier_midpoint(frontier) -> np.ndarray:
    """Given a list of contiguous points (numpy arrays) representing a frontier, first
    calculate the total length of the frontier, then find the midpoint of the
    frontier"""
    # First, reshape and expand the frontier to be a 2D array of shape (X, 2, 2)
    # representing line segments between adjacent points
    line_segments = np.concatenate((frontier[:-1], frontier[1:]), axis=1).reshape(
        (-1, 2, 2)
    )
    # Calculate the length of each line segment
    line_lengths = np.sqrt(
        np.square(line_segments[:, 0, 0] - line_segments[:, 1, 0])
        + np.square(line_segments[:, 0, 1] - line_segments[:, 1, 1])
    )
    if len(frontier) < 2:
        return frontier[0][0].astype(np.float64)
    cum_sum = np.cumsum(line_lengths)
    total_length = cum_sum[-1]
    # Find the midpoint of the frontier
    half_length = total_length / 2
    # Find the line segment that contains the midpoint
    line_segment_idx = np.argmax(cum_sum > half_length)
    # Calculate the coordinates of the midpoint
    line_segment = line_segments[line_segment_idx]
    line_length = line_lengths[line_segment_idx]
    # Use the difference between the midpoint length and cumsum
    # to find the proportion of the line segment that the midpoint is at
    length_up_to = cum_sum[line_segment_idx - 1] if line_segment_idx > 0 else 0
    proportion = (half_length - length_up_to) / line_length
    # Calculate the midpoint coordinates
    midpoint = line_segment[0] + proportion * (line_segment[1] - line_segment[0])
    return midpoint


def get_closest_frontier_point(xy, frontier):
    """Returns the point on the frontier closest to the given coordinate."""
    # First, reshape and expand the frontier to be a 2D array of shape (X, 2)
    # representing line segments between adjacent points
    line_segments = np.concatenate([frontier[:-1], frontier[1:]], axis=1).reshape(
        (-1, 2, 2)
    )
    closest_segment, closest_point = closest_line_segment(xy, line_segments)
    return closest_point

def _outward_vector(point, unknown):
    """Image-space unit vector from a boundary point into nearby unknown.

    This is the direction that matters for a frontier and the one the code
    never had: the yaw stored with a frontier was arctan2 of robot->frontier,
    i.e. the way you happened to walk up to it. Standing on a frontier facing
    that heading points you at whatever was behind it -- a wall, most of the
    time -- instead of at the unexplored space you came to see.
    """
    cx, cy = int(round(point[0])), int(round(point[1]))
    h, w = unknown.shape
    r = OUTWARD_LOOK
    y0, y1 = max(0, cy - r), min(h, cy + r + 1)
    x0, x1 = max(0, cx - r), min(w, cx + r + 1)
    ys, xs = np.nonzero(unknown[y0:y1, x0:x1])
    if ys.size == 0:
        return None
    dx = float(xs.mean() + x0 - cx)
    dy = float(ys.mean() + y0 - cy)
    norm = np.hypot(dx, dy)
    if norm < 1e-6:
        return None
    return dx / norm, dy / norm


def _gap_width_m(seg, lethal, resolution):
    """Wall-to-wall gap across the frontier, in metres (>= GAP_PROBE_M*2 if open)."""
    a, b = seg[0][0].astype(float), seg[-1][0].astype(float)
    mid = seg[len(seg) // 2][0].astype(float)
    t = b - a
    n = float(np.hypot(*t))
    if n < 1e-6:
        return GAP_PROBE_M * 2
    t /= n
    h, w = lethal.shape
    steps = int(GAP_PROBE_M / resolution)
    total = 0.0
    for sgn in (1.0, -1.0):
        d = GAP_PROBE_M
        for k in range(1, steps + 1):
            x = int(round(mid[0] + sgn * t[0] * k)); y = int(round(mid[1] + sgn * t[1] * k))
            if not (0 <= x < w and 0 <= y < h):
                break
            if lethal[y, x]:
                d = k * resolution
                break
        total += d
    return total


CLEAR_M = float(os.environ.get('REASONNAV_FRONTIER_CLEAR_M', '0.6'))   # >= inscribed 0.41
# What the last costmap_to_frontiers() call did, stage by stage, for the
# refresh timer to report and to dump as an image when nothing comes out.
LAST_DEBUG = {}


def _clear_point(seg, pt, dt, resolution):
    """Point on/near the segment with at least CLEAR_M of wall clearance."""
    h, w = dt.shape
    need = CLEAR_M / resolution
    xs = np.clip(seg[:, 0, 0], 0, w - 1); ys = np.clip(seg[:, 0, 1], 0, h - 1)
    vals = dt[ys, xs]
    k = int(np.argmax(vals))
    x, y = float(xs[k]), float(ys[k])
    if vals[k] >= need:
        # Prefer the arc midpoint when it is already clear -- it is the natural
        # centre of the opening -- and the clearest point otherwise.
        px, py = int(round(pt[0])), int(round(pt[1]))
        if 0 <= px < w and 0 <= py < h and dt[py, px] >= need:
            return pt
        return np.array([x, y], dtype=float)
    # Walk up the distance gradient (away from the nearest wall).
    for _ in range(int(1.5 / resolution)):
        xi, yi = int(round(x)), int(round(y))
        if not (1 <= xi < w - 1 and 1 <= yi < h - 1):
            break
        gx = dt[yi, xi + 1] - dt[yi, xi - 1]; gy = dt[yi + 1, xi] - dt[yi - 1, xi]
        n = float(np.hypot(gx, gy))
        if n < 1e-6:
            break
        x += gx / n; y += gy / n
        if dt[int(round(y)), int(round(x))] >= need:
            break
    return np.array([x, y], dtype=float)


def costmap_to_frontiers(costmap, resolution=0.1, robot_px=None):
    """Waypoints on the boundary between explored free space and the unknown.

    The mask this used to build was

        np.logical_and(costmap < 253, costmap > 10) -> 0, else 255

    which never looks at UNKNOWN at all: it marks the inflation band and calls
    everything else -- free floor, walls, unexplored -- a frontier. So the
    navigable contour was accepted almost in its entirety, including the
    stretches that simply run along a wall, and stars appeared in places with
    nothing behind them to go and see.

    A frontier is free space that BORDERS the unknown, so that is what is
    tested here.
    """
    # Real obstacles only. Testing against 253 folded the inflation layer into
    # the geometry, and inflation is not geometry: with a 0.41 m inscribed
    # radius it eats 0.82 m out of every corridor, and the 5x5 dilation below
    # takes another 0.4 m. A 1.2 m doorway came out as solid wall, so the
    # contour never went through it and the opening produced no frontier at
    # all. Whether the rig actually fits is a separate question, and
    # filter_frontiers_by_cost answers it against the inflated costmap.
    obstacle = ((costmap == LETHAL_OBSTACLE) |
                (costmap == NO_INFORMATION)).astype(np.uint8) * 255
    obstacle_dilated = cv2.dilate(obstacle, np.ones((5, 5), np.uint8), iterations=1)
    navigable = np.where(obstacle_dilated == 0, 255, 0).astype(np.uint8)

    # Cells within UNKNOWN_REACH of unexplored ground. Reach is a couple of
    # cells because the contour is traced on the dilated map and so sits just
    # inside the free region rather than exactly on the boundary.
    unknown = (costmap == NO_INFORMATION).astype(np.uint8)
    near_unknown = cv2.dilate(
        unknown, np.ones((3, 3), np.uint8), iterations=UNKNOWN_REACH)

    # ...and far enough from a wall that standing there is plausible. Without
    # this the boundary where a wall meets unmapped space counts as frontier,
    # which is the corridor's edge, not a way out of it.
    lethal = (costmap == LETHAL_OBSTACLE)
    near_wall = cv2.dilate(
        lethal.astype(np.uint8), np.ones((3, 3), np.uint8), iterations=WALL_CLEARANCE)

    costmap_mask = np.where(
        (near_unknown > 0) & (near_wall == 0), 255, 0).astype(np.uint8)
    # costmap_mask = cv2.dilate(
    #         costmap_mask,
    #         np.ones((11, 11), np.uint8),
    #         iterations=1,
    #     )
    # filtered_explored_mask = filter_out_small_unexplored(
    #     full_map, explored_mask, area_thresh
    # )
    # Only the free region the robot is standing in. "Largest contour" was
    # not that region whenever a glass wall or a doorway seen through a window
    # made another blob bigger, and a frontier on the far side of a wall the
    # rig cannot get through was offered -- and chosen -- as a goal. A
    # frontier is somewhere you can walk to, by definition.
    n_lab, labels = cv2.connectedComponents(navigable, connectivity=8)
    region = None
    if robot_px is not None:
        rc, rr = int(round(robot_px[0])), int(round(robot_px[1]))
        h, w = labels.shape
        if 0 <= rc < w and 0 <= rr < h and labels[rr, rc] > 0:
            region = labels[rr, rc]
        else:
            # Robot cell itself is inside the 5x5 obstacle dilation (hugging a
            # wall): take the nearest navigable cell within a metre.
            r = int(1.0 / resolution)
            win = labels[max(0, rr - r):rr + r + 1, max(0, rc - r):rc + r + 1]
            ys, xs = np.nonzero(win)
            if xs.size:
                k = int(np.argmin((xs - min(rc, r)) ** 2 + (ys - min(rr, r)) ** 2))
                region = win[ys[k], xs[k]]
    if region is None:
        areas = np.bincount(labels.ravel()); areas[0] = 0
        region = int(np.argmax(areas)) if areas.size > 1 else 0
    mine = np.where(labels == region, 255, 0).astype(np.uint8)
    LAST_DEBUG.clear()
    LAST_DEBUG.update(components=int(n_lab - 1), navigable_cells=int((navigable > 0).sum()),
                      robot_cells=int((mine > 0).sum()), robot_px=robot_px, robot_in_navigable=bool(region is not None))

    # Reachable through passages at least MIN_GAP_M wide. Eroding the free
    # region by half that width pinches every narrower passage shut; whatever
    # is then no longer connected to the robot lies behind a door or gap the
    # rig cannot pass, however wide the room beyond it is. (The per-frontier
    # gap test only measures the gap AT the frontier, not on the way to it.)
    # `navigable` already carries a 2-cell obstacle dilation, so the erosion
    # radius is (MIN_GAP_M - 2*2*res) / 2.
    # Erosion by r removes navigable runs narrower than 2r+1 cells; navigable
    # is the true gap minus 4 cells of obstacle dilation. Cut exactly the gaps
    # under MIN_GAP_M: 2r+1 = MIN_GAP_M/res - 4  ->  r = (MIN_GAP_M/res - 5) / 2.
    r_cells = max(1, int(round((MIN_GAP_M / resolution - 5) / 2.0)))   # 1.5/0.1 is 14.999.. in float
    kern = np.ones((2 * r_cells + 1, 2 * r_cells + 1), np.uint8)
    wide = cv2.erode(mine, kern)
    # Where the robot stands is passable by definition -- it is standing there.
    # Without this the camera's own wedge, narrow at its apex, was cut right in
    # front of the sensor and every frontier on the far arc was "unreachable"
    # from the first second of a run; the same happened standing in a doorway.
    if robot_px is not None:
        rc0, rr0 = int(round(robot_px[0])), int(round(robot_px[1]))
        seed = np.zeros_like(mine)
        cv2.circle(seed, (rc0, rr0), int(1.2 / resolution), 255, -1)
        wide = cv2.bitwise_or(wide, cv2.bitwise_and(seed, mine))
    n_w, lab_w = cv2.connectedComponents(wide, connectivity=8)
    reach = None
    if n_w > 1:
        if robot_px is not None:
            rc, rr = int(round(robot_px[0])), int(round(robot_px[1]))
            rr_ = int(1.5 / resolution)
            win = lab_w[max(0, rr - rr_):rr + rr_ + 1, max(0, rc - rr_):rc + rr_ + 1]
            vals = win[win > 0]
            reg_w = int(np.bincount(vals).argmax()) if vals.size else None
        else:
            areas = np.bincount(lab_w.ravel()); areas[0] = 0
            reg_w = int(np.argmax(areas))
        if reg_w:
            reach = cv2.dilate(np.where(lab_w == reg_w, 255, 0).astype(np.uint8), kern)
    LAST_DEBUG.update(erode_cells=r_cells, eroded_components=int(n_w - 1),
                      reach_cells=int((reach > 0).sum()) if reach is not None else None, mine=mine, reach=reach)
    contours, _ = cv2.findContours(mine, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    frontiers = []
    contours = sorted(contours, key=cv2.contourArea, reverse=True)[:1]
    if len(contours) == 0:
        return frontiers, []
    contour = contours[0]
    c = interpolate_contour(contour)
    c = contour_to_frontiers(c, costmap_mask)
    lethal_mask = (costmap == LETHAL_OBSTACLE)
    all_segs = list(c)
    gap_ok = [(_gap_width_m(seg, lethal_mask, resolution) >= MIN_GAP_M) for seg in all_segs]
    def _in_reach(seg):
        if reach is None:
            return True
        pts_ = seg[::max(1, len(seg) // 5), 0, :]
        h_, w_ = reach.shape
        return any(0 <= int(x) < w_ and 0 <= int(y) < h_ and reach[int(y), int(x)] for x, y in pts_)
    reach_ok = [_in_reach(seg) for seg in all_segs]
    LAST_DEBUG.update(segments=len(all_segs), gap_ok=int(sum(gap_ok)),
                      reach_ok=int(sum(g_ and r_ for g_, r_ in zip(gap_ok, reach_ok))),
                      seg_list=all_segs, seg_keep=[g_ and r_ for g_, r_ in zip(gap_ok, reach_ok)])
    c = [seg for seg, g_, r_ in zip(all_segs, gap_ok, reach_ok) if g_ and r_]
    if not c:
        LAST_DEBUG['final'] = 0
        return [], []
    points = frontier_waypoints(c)
    # A waypoint hugging a wall is thrown out downstream (inscribed cost) and
    # the corridor it stood for vanishes from the candidates. Slide each one
    # to the clearest point of its segment, and if the whole segment runs
    # along a wall step it out to CLEAR_M of clearance.
    dt = cv2.distanceTransform((~lethal_mask).astype(np.uint8), cv2.DIST_L2, 3)
    points = np.array([_clear_point(seg, pt, dt, resolution) for seg, pt in zip(c, points)])
    LAST_DEBUG['final'] = len(points)
    unknown = (costmap == NO_INFORMATION).astype(np.uint8)
    dirs = []
    for p in points:
        # The waypoint stays ON the boundary. Nudging it toward nearby unknown
        # sounded right and was not: what lies immediately behind a wall is
        # also unknown, so the nudge pushed goals into -- and through -- walls.
        frontiers.append(p)
        dirs.append(_outward_vector(p, unknown))
    return frontiers, dirs
    # for contour in contours:
    #     if cv2.contourArea(contour) < 800:
    #         continue
    #     c = interpolate_contour(contour)
    #     c = contour_to_frontiers(c, costmap_mask)
    #     if len(c) == 0:
    #         continue
    #     points = frontier_waypoints(c)
    #     for p in points:
    #         frontiers.append(p)
    #     break
    return frontiers

def get_frontiers(costmap:OccupancyGrid, robot_tf:Transform):
    costmap_indexer = PyCostmap2D(costmap)
    costmap_image = costmap_indexer.get_costmap_as_image()
    robot_px = None
    try:
        rx = robot_tf.translation.x; ry = robot_tf.translation.y
        mx, my = costmap_indexer.worldToMapValidated(wx=rx, wy=ry, scale=1)
        if mx is not None:
            robot_px = (mx, my)
    except Exception:
        pass
    frontiers, dirs = costmap_to_frontiers(costmap_image, costmap_indexer.resolution, robot_px)
    frontiers_world = []
    yaws = []
    for frontier, d in zip(frontiers, dirs):
        wx, wy = costmap_indexer.mapToWorld(frontier[0], frontier[1])
        frontiers_world.append((wx, wy))
        # get_costmap_as_image transposes and flips both axes, so an image
        # step of (dcol, drow) is a world step of (-drow, -dcol).
        yaws.append(None if d is None else float(np.arctan2(-d[0], -d[1])))
    return frontiers, frontiers_world, yaws
    
def visualize_frontiers(frontiers, costmap:OccupancyGrid, robot_tf:Transform):
    costmap_indexer = PyCostmap2D(costmap)
    costmap_image = costmap_indexer.get_costmap_as_image().copy()
    # costmap_image = costmap_indexer.costmap.copy()
    # costmap_image = costmap_image.reshape(costmap_indexer.size_y, costmap_indexer.size_x, order='A')
    costmap_image = cv2.cvtColor(costmap_image, cv2.COLOR_GRAY2BGRA).astype(np.uint8)
    costmap_image = cv2.resize(costmap_image, (costmap_indexer.size_y*5, costmap_indexer.size_x*5), interpolation=cv2.INTER_NEAREST)
    robot_x, robot_y, robot_yaw = transform_msg_to_xyyaw(robot_tf)
    mx, my = costmap_indexer.worldToMapValidated(wx=robot_x, wy=robot_y)
    robot_color = (0, 0, 255)
    costmap_image = cv2.circle(costmap_image, tuple([mx*5, my*5]), 5, robot_color, -1)

    for i, (frontier_x, frontier_y) in enumerate(frontiers):
        center_x = int(frontier_x * 5)
        center_y = int(frontier_y * 5)
        costmap_image = cv2.circle(costmap_image, tuple([center_x, center_y]), 5, (0, 255, 0), -1)
        costmap_image = cv2.putText(
            costmap_image, f'{i}', tuple([center_x, center_y+5]), 
            cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 1, cv2.LINE_AA)
    # scale image in half of current size
    costmap_image = cv2.resize(costmap_image, (costmap_indexer.size_y*3, costmap_indexer.size_x*3), interpolation=cv2.INTER_NEAREST)
    return costmap_image
if __name__ == "__main__":
    import argparse
    import time

    import matplotlib.pyplot as plt

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f", "--full_map", help="Path to full map image", default="full_map.png"
    )
    parser.add_argument(
        "-e",
        "--explored_mask",
        help="Path to explored map image",
        default="explored_mask.png",
    )
    parser.add_argument(
        "-a",
        "--area_thresh",
        help="Minimum unexplored area (in pixels) needed adjacent to a frontier for"
        "that frontier to be valid",
        type=float,
        default=-1,
    )
    parser.add_argument(
        "-n",
        "--num-iterations",
        help="Number of iterations to run the algorithm for timing purposes. Set to "
        "0 for no timing",
        type=int,
        default=500,
    )
    args = parser.parse_args()

    if VISUALIZE:
        args.num_iterations = 0

    # Read in the map
    full_map = cv2.imread(args.full_map, 0)
    # Read in the explored map
    explored_mask = cv2.imread(args.explored_mask, 0)
    times = []
    for _ in range(args.num_iterations + 1):
        start_time = time.time()
        waypoints = detect_frontier_waypoints(full_map, explored_mask, args.area_thresh)
        times.append(time.time() - start_time)
    if args.num_iterations > 0:
        # Skip first run as it's slower due to JIT compilation
        print(
            f"Avg. time taken for algorithm over {args.num_iterations} runs:",
            np.mean(times[1:]),
        )

    # Plot the results
    plt.figure(figsize=(10, 10))
    plt.imshow(full_map, cmap="gray")
    plt.imshow(explored_mask, cmap="gray", alpha=0.5)
    for waypoint in waypoints:
        plt.scatter(waypoint[0], waypoint[1], c="red", s=50)
    plt.show()