from visualization_msgs.msg import Marker, MarkerArray
from rclpy.time import Time
import copy
import math
import numpy as np
from nav2_msgs.msg import Costmap
from mm_dev.common.costmap_2d import PyCostmap2D
import cv2
from geometry_msgs.msg import Pose
from mm_dev.common.tf_utils import pose_msg_to_xyyaw
import pickle
import os
from enum import Enum
from PIL import Image, ImageDraw, ImageFont


def _assets_dir():
    """Locate the repo's assets/ (upstream hardcodes /home/user/colcon_ws)."""
    if os.environ.get('REASONNAV_ASSETS'):
        return os.environ['REASONNAV_ASSETS']
    # .../ReasonNav/src/mm_dev/mm_dev/common/vis_utils.py -> .../ReasonNav/assets
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, '..', '..', '..', '..'))
    candidate = os.path.join(repo, 'assets')
    if os.path.isdir(candidate):
        return candidate
    return os.path.expanduser('~/tips_ws/src/ReasonNav/assets')


ASSETS_DIR = _assets_dir()

class Color(Enum):
    RED = (0, 0, 255)
    GREEN = (0, 255, 0)
    BLUE = (255, 0, 0)
    YELLOW = (0, 255, 255)
    CYAN = (255, 255, 0)
    MAGENTA = (255, 0, 255)
    WHITE = (255, 255, 255)
    BLACK = (0, 0, 0)
    GRAY = (128, 128, 128)

class GrayColor(Enum):
    BLACK = 0
    WHITE = 255

def xyyaw_to_marker(t:Time, name, x, y, yaw, rgb=(1.0, 0.0, 0.0), scale=(0.5, 0.1, 0.1)):
    """Arrow marker at (x, y) pointing along yaw.

    rgb/scale default to the small red arrow used for frontier candidates;
    override them so the chosen goal stands out from them in rviz.
    """
    marker = Marker()
    marker.header.frame_id = 'map'
    marker.header.stamp = t.to_msg()
    marker.ns = name
    marker.id = 0
    marker.type = Marker.ARROW
    marker.action = Marker.ADD
    marker.pose.position.x = x
    marker.pose.position.y = y
    marker.pose.position.z = 0.0
    marker.pose.orientation.x = 0.0
    marker.pose.orientation.y = 0.0
    marker.pose.orientation.z = np.sin(yaw / 2)
    marker.pose.orientation.w = np.cos(yaw / 2)
    marker.scale.x = scale[0]
    marker.scale.y = scale[1]
    marker.scale.z = scale[2]
    marker.color.a = 1.0
    marker.color.r = rgb[0]
    marker.color.g = rgb[1]
    marker.color.b = rgb[2]
    return marker

_ICON_CACHE = {}


def _load_icon(path, size):
    """Decoded, resized icon, kept in memory.

    insert_image used to re-open the PNG from disk and resize it on every
    call -- once per landmark, every render, thirty times a frame.
    """
    key = (path, size)
    hit = _ICON_CACHE.get(key)
    if hit is None:
        img = Image.open(path).resize(size).convert('RGBA')
        arr = np.array(img)
        hit = (arr[:, :, :3], (arr[:, :, 3] / 255.0)[:, :, None])
        _ICON_CACHE[key] = hit
    return hit


def _rects_overlap(a, b, pad=2):
    return not (a[2] + pad <= b[0] or b[2] + pad <= a[0] or
                a[3] + pad <= b[1] or b[3] + pad <= a[1])


def insert_image(base_image, overlay_image_path, position=(0, 0), size=(100, 100),
                 label_text=None, label_font=cv2.FONT_HERSHEY_SIMPLEX, label_size=0.8,
                 label_color=(255, 255, 255), label_thickness=2, label_bg_color=(0, 0, 0),
                 label_boxes=None):
    """Stamp an icon onto the map, optionally with a numbered tag.

    label_boxes, when given, is a running list of tags already placed on this
    image. A new tag is nudged to the first free slot around its icon instead of
    landing on top of them: doors in this building sit about a metre apart,
    which at the map's 20 px/m is closer together than the tags are wide, so
    without this the numbers pile into an unreadable stack.
    """
    # The caller hands in a 4-channel canvas and converts once for the whole
    # frame. Converting BGR->RGBA and back inside here cost two full-image
    # copies per icon, which at thirty landmarks was most of the render.
    incoming_bgr = base_image.shape[2] == 3
    if incoming_bgr:
        base_image = cv2.cvtColor(base_image, cv2.COLOR_BGR2RGBA)

    overlay_rgb, overlay_alpha = _load_icon(overlay_image_path, size)
    overlay_width, overlay_height = size
    
    # Specify the position to insert the overlay image
    x_offset, y_offset = position
    # subtract half overlay width and height from the position to center the overlay
    x_offset -= overlay_width // 2
    y_offset -= overlay_height // 2
    # Ensure the position is within the bounds of the base image
    x_offset = max(0, min(x_offset, base_image.shape[1] - overlay_width))
    y_offset = max(0, min(y_offset, base_image.shape[0] - overlay_height))
    # Make sure the overlay fits within the base image
    if x_offset + overlay_width > base_image.shape[1]:
        overlay_width = base_image.shape[1] - x_offset
    if y_offset + overlay_height > base_image.shape[0]:
        overlay_height = base_image.shape[0] - y_offset

    if overlay_width > 0 and overlay_height > 0:
        roi = base_image[y_offset:y_offset + overlay_height,
                         x_offset:x_offset + overlay_width, :3]
        a = overlay_alpha[:overlay_height, :overlay_width]
        roi[:] = (overlay_rgb[:overlay_height, :overlay_width] * a +
                  roi * (1 - a)).astype(np.uint8)
    if label_text:
        text_size, _ = cv2.getTextSize(label_text, label_font, label_size, label_thickness)
        text_width, text_height = text_size
        pad = 3
        box_w, box_h = text_width + 2 * pad, text_height + 2 * pad
        H, W = base_image.shape[:2]
        icon_cx = x_offset + overlay_width // 2
        icon_cy = y_offset + overlay_height // 2

        # Slots around the icon, closest first, spiralling outwards.
        gap = 3
        cands = []
        for ring in range(6):
            out = ring * (box_h + gap)
            cands += [
                (icon_cx - box_w // 2, y_offset - gap - box_h - out),        # above
                (icon_cx - box_w // 2, y_offset + overlay_height + gap + out),  # below
                (x_offset + overlay_width + gap + out, icon_cy - box_h // 2),   # right
                (x_offset - gap - box_w - out, icon_cy - box_h // 2),           # left
            ]

        placed = label_boxes if label_boxes is not None else []
        chosen = None
        for bx, by in cands:
            bx = max(0, min(bx, W - box_w))
            by = max(0, min(by, H - box_h))
            rect = (bx, by, bx + box_w, by + box_h)
            if not any(_rects_overlap(rect, r) for r in placed):
                chosen = rect
                break
        if chosen is None:                      # crowded beyond saving
            bx = max(0, min(icon_cx - box_w // 2, W - box_w))
            by = max(0, min(y_offset - gap - box_h, H - box_h))
            chosen = (bx, by, bx + box_w, by + box_h)
        placed.append(chosen)

        bx, by, bx2, by2 = chosen
        # A nudged tag can end up well away from its icon, so tie the two
        # together rather than leaving the reader to guess.
        lab_cx, lab_cy = (bx + bx2) // 2, (by + by2) // 2
        if abs(lab_cx - icon_cx) > overlay_width or abs(lab_cy - icon_cy) > overlay_height:
            cv2.line(base_image, (lab_cx, lab_cy), (icon_cx, icon_cy),
                     (30, 30, 30, 255), 1, cv2.LINE_AA)

        cv2.rectangle(base_image, (bx, by), (bx2, by2), label_bg_color, -1)
        cv2.putText(base_image, label_text, (bx + pad, by2 - pad),
                    label_font, label_size, label_color, label_thickness, cv2.LINE_AA)
    
    if incoming_bgr:
        return cv2.cvtColor(base_image, cv2.COLOR_RGBA2BGR)
    return base_image

# Padding kept around the mapped area when cropping, and the smallest crop we
# will emit. Both in costmap cells, since the crop now happens before scaling.
CROP_MARGIN_CELLS = 25
CROP_MIN_CELLS = 80

# Icon sizes in final output pixels. The old 50 px door icon was applied at the
# map's own scale, where it covered 2.5 m of corridor -- wider than the gap
# between two doors, which is why they merged into one orange smear.
# Icons and labels are stamped AFTER the map has been scaled to its output
# size, so these are final on-screen pixels and stay the same whether the run
# has covered five metres or fifty. Drawing them before the scale (as this used
# to) shrank the numbers along with the map until they were unreadable.
ROBOT_ICON_PX = 30
FRONTIER_ICON_PX = 20
LANDMARK_ICON_PX = 26
LABEL_FONT_SIZE = 0.5
LABEL_THICKNESS = 1

# Longest side of the map area before the compass border is added. The map is
# scaled to this whatever its extent -- down for a large run, up for a small
# one, capped so an almost-empty map is not a handful of giant cells.
MAP_OUTPUT_PX = int(os.environ.get('REASONNAV_MAP_OUTPUT_PX', '1400'))
MAP_MAX_UPSCALE = 6.0

# A frontier is only a frontier while unexplored ground still borders it. The
# list is recomputed by the navigation loop once every 5-30 s (it costs ~40 ms,
# too much for the 5 Hz render), but the map underneath keeps filling in -- so a
# star computed on the boundary ends up sitting in the middle of open floor a
# few seconds later, pointing at nothing. Cheap to re-check here, where the grid
# is already in hand: look for unknown cells in a window around the star.
FRONTIER_STALE_CELLS = int(os.environ.get('REASONNAV_FRONTIER_STALE_CELLS', '6'))

# Cardinal labels on the border are axis names for THIS map frame, not compass
# bearings -- there is no GPS or magnetometer here, and nothing needs there to
# be. Every consumer (the rendered image, keypoints_dict positions, the bearing
# a sign photo resolves to) lives in the same frame, so "north" only has to mean
# the same direction each time, which it does.
#
# The map is drawn with +x up and +y left. Starting the rig pointed along the
# corridor therefore lays the corridor out vertically, which keeps the crop
# tight on its own -- no rotation needed, and none applied: turning the map by
# a computed angle made every frame's orientation depend on how much had been
# explored, which is a poor thing to ask anyone to re-read each update.
# Obstacles come out of nav2 one cell thick, which is 2 px on this map and
# effectively invisible next to the icons. Fatten them so a wall reads as a
# wall; purely cosmetic, the costmap itself is untouched.
OBSTACLE_DILATE_CELLS = 3


def _crop_to_observed(costmap, margin_cells=40):
    """Shrink a 240 x 240 m grid message to the part that has been observed.

    Everything downstream converts the whole grid to a cost image on every
    render; at 2400 x 2400 cells that alone took 1.8 s per frame once the map
    had grown, on a timer meant to run at 2 Hz. The unobserved sea around the
    building carries nothing, so cut it away first and re-anchor the origin.
    Works for both nav_msgs/OccupancyGrid (-1 = unknown) and nav2 Costmap
    (255 = unknown); returns the input untouched if it cannot be cropped.
    """
    try:
        if hasattr(costmap, 'info'):
            w, h, res = costmap.info.width, costmap.info.height, costmap.info.resolution
            ox, oy = costmap.info.origin.position.x, costmap.info.origin.position.y
            g = np.asarray(costmap.data, dtype=np.int16).reshape(h, w)
            known = g != -1
        else:
            m = costmap.metadata
            w, h, res = m.size_x, m.size_y, m.resolution
            ox, oy = m.origin.position.x, m.origin.position.y
            g = np.asarray(costmap.data, dtype=np.uint8).reshape(h, w)
            known = g != 255
        rows = np.flatnonzero(known.any(axis=1)); cols = np.flatnonzero(known.any(axis=0))
        if rows.size == 0:
            return costmap
        y0, y1 = max(0, rows[0] - margin_cells), min(h, rows[-1] + margin_cells + 1)
        x0, x1 = max(0, cols[0] - margin_cells), min(w, cols[-1] + margin_cells + 1)
        if (y1 - y0) * (x1 - x0) > 0.6 * w * h:
            return costmap                     # nothing worth cropping
        sub = g[y0:y1, x0:x1]
        out = copy.deepcopy(costmap)
        if hasattr(costmap, 'info'):
            out.info.width, out.info.height = int(x1 - x0), int(y1 - y0)
            out.info.origin.position.x = ox + x0 * res
            out.info.origin.position.y = oy + y0 * res
            out.data = sub.astype(np.int8).reshape(-1).tolist()
        else:
            out.metadata.size_x, out.metadata.size_y = int(x1 - x0), int(y1 - y0)
            out.metadata.origin.position.x = ox + x0 * res
            out.metadata.origin.position.y = oy + y0 * res
            out.data = sub.astype(np.uint8).reshape(-1).tolist()
        return out
    except Exception:
        return costmap


def vis_landmarks(costmap:Costmap, frontier_dict, landmark_dict, robot_pose:Pose):
    costmap = _crop_to_observed(costmap)
    FONT_SIZE = 0.5
    THICKNESS = 1
    MARKER_SIZE = 20
    BORDER_WIDTH = 30  # Width of the border for cardinal directions
    
    costmap_indexer = PyCostmap2D(costmap)
    # costmap_image = costmap_indexer.costmap.copy()
    costmap_image = costmap_indexer.get_costmap_as_image().copy()

    # # filter out inflation layer
    mask = (costmap_image > GrayColor.BLACK.value) & (costmap_image < GrayColor.WHITE.value - 50)
    costmap_image[mask] = np.where(costmap_image[mask] > GrayColor.BLACK.value + 100, 200, GrayColor.BLACK.value)
    # cv2.imwrite('global_costmap_landmarks_init.jpg', costmap_image)
    
    # costmap_image = costmap_image.reshape(costmap_indexer.size_y, costmap_indexer.size_x)
    # cv2.imwrite('global_costmap_landmarks_reshape.jpg', costmap_image)
    # Add robot position
    robot_x, robot_y, robot_yaw = pose_msg_to_xyyaw(robot_pose)
    
    # flip the image to match the orientation of the costmap
    costmap_image_gray = costmap_image.copy()
    costmap_image = cv2.cvtColor(costmap_image, cv2.COLOR_GRAY2BGR).astype(np.uint8)
    costmap_image[np.where(costmap_image_gray == GrayColor.BLACK.value)] = Color.GREEN.value
    costmap_image[np.where(costmap_image_gray == GrayColor.WHITE.value)] = Color.GRAY.value
    
    # for values between 1 and 254 in costmap_image_gray, use a gradient colormap of red and assign the new color
    # to the costmap_image
    # cv2.applyColorMap returns None for an empty input, and .reshape on that
    # kills the node. A sparse costmap (narrow FOV, tight height band) really
    # can have no cells in the inflation range, so skip the tint when empty.
    gradient = np.where((costmap_image_gray > GrayColor.BLACK.value) &
                        (costmap_image_gray < GrayColor.WHITE.value))
    if gradient[0].size:
        costmap_image[gradient] = cv2.applyColorMap(
            255 - costmap_image_gray[gradient] // 8, cv2.COLORMAP_JET).reshape(-1, 3)


    # LETHAL (254) and INSCRIBED (253) are the actual walls. The JET tint above
    # already colours them red, but one cell wide they vanish under the icons
    # and survive the publish-time downscale only as speckle. Redraw them solid
    # and dilated so the corridor has visible edges.
    # Bounded above as well: UNKNOWN is 255 and would otherwise be swept in,
    # painting the entire unexplored map red.
    obstacles = ((costmap_image_gray >= 253) &
                 (costmap_image_gray < GrayColor.WHITE.value))
    if obstacles.any() and OBSTACLE_DILATE_CELLS > 1:
        k = np.ones((OBSTACLE_DILATE_CELLS, OBSTACLE_DILATE_CELLS), np.uint8)
        thick = cv2.dilate(obstacles.astype(np.uint8), k).astype(bool)
        costmap_image[thick] = Color.RED.value

    # The map stays at one pixel per cell until the output scale is known; the
    # old fixed 2x upsample only made every later step more expensive.

    keypoints_dict = {}
    index = 0
    # Cell-resolution pixel positions of everything that will be drawn. Nothing
    # is stamped yet: the crop and the output scale have to be settled first so
    # icons and text can be sized in final pixels.
    pending = []          # (kind, cell_x, cell_y, label_text or None)
    drawn_pixels = []

    # Place robot icon
    robot_icon = os.path.join(ASSETS_DIR, 'robot_icon.png')
    img_x, img_y = costmap_indexer.worldToMapValidated(wx=robot_x, wy=robot_y, scale=1)
    if (img_x, img_y) != (None, None):
        pending.append((robot_icon, img_x, img_y, ROBOT_ICON_PX, None))
        drawn_pixels.append((img_x, img_y))
        keypoints_dict[index] = {'name': "you, the robot"}
        index += 1
    
    # Place frontiers
    star_icon = os.path.join(ASSETS_DIR, 'star_icon.png')
    
    for name, value in frontier_dict.items():
        frontier_x, frontier_y = value['position_xy']
        img_x, img_y = costmap_indexer.worldToMapValidated(wx=frontier_x, wy=frontier_y, scale=1)
        if (img_x, img_y) == (None, None):
            continue
        # Drop the ones the map has since caught up with. Frontier_ahead is
        # not a frontier: it is deliberately placed on known free ground down
        # the corridor, so this test threw it out on most passes and the VLM
        # was left with nothing ahead (and picked a door 36 m back).
        r = FRONTIER_STALE_CELLS
        win = costmap_image_gray[max(0, img_y - r):img_y + r + 1,
                                 max(0, img_x - r):img_x + r + 1]
        if name != 'Frontier_ahead' and win.size and not (win == GrayColor.WHITE.value).any():
            continue
        pending.append((star_icon, img_x, img_y, FRONTIER_ICON_PX, str(index)))
        drawn_pixels.append((img_x, img_y))
        keypoints_dict[index] = {'name': name, 'position': (frontier_x, frontier_y)}
        # keypoints_dict[index] = {'name': name}
        index += 1

    # Place landmarks
    door_icon = os.path.join(ASSETS_DIR, 'door_icon.png')
    compass_icon = os.path.join(ASSETS_DIR, 'compass_icon.png')
    human_icon = os.path.join(ASSETS_DIR, 'human_icon.png')
    
    for name, value in landmark_dict.items():
        icon = None
        dirs = None
        info = None
        if 'door' in name:
            icon = door_icon
        elif 'sign' in name:
            icon = compass_icon
            # No 'directions' here on purpose. Signs used to arrive as a
            # cardinal dict ({'West': ['T131-T150']}), which quantised an exact
            # bearing into one of eight buckets and dropped the geometry that
            # made it readable. The chooser now receives the sign's photograph
            # instead -- see VLMNav._sign_context.
        elif 'person' in name:  # Add handling for person icons
            icon = human_icon
            if 'Visited' in name:
                try:
                    info = value['info']
                except:
                    print("No information found")
            
        if icon == None:
            continue
            
        landmark_x, landmark_y = value['position_xy']
        img_x, img_y = costmap_indexer.worldToMapValidated(wx=landmark_x, wy=landmark_y, scale=1)
        if (img_x, img_y) != (None, None):
            pending.append((icon, img_x, img_y, LANDMARK_ICON_PX, str(index)))
            drawn_pixels.append((img_x, img_y))
        entry = {'name': name,
                 'position': (round(landmark_x, 2), round(landmark_y, 2))}
        # The number actually read off a door, when there is one. Separate from
        # the name so an unread door carries no number at all.
        if value.get('room') is not None:
            entry['room'] = value['room']
        if dirs:
            entry['directions'] = dirs
        elif info:
            entry['info'] = info
        keypoints_dict[index] = entry
        index += 1
    
    # --- Crop, scale, then draw ------------------------------------------
    # The costmap is a fixed 120 x 120 m canvas but a run only ever occupies a
    # corner of it, so the crop trims the blank UNKNOWN margin. The scale that
    # follows is what keeps the numbers readable: the map is resized FIRST and
    # the icons and text stamped on afterwards at fixed pixel sizes, so a
    # fifty-metre run gets the same legible tags as a five-metre one.
    ys, xs = np.where(costmap_image_gray != GrayColor.WHITE.value)
    x_lo, x_hi, y_lo, y_hi = [], [], [], []
    if ys.size:
        x_lo.append(int(xs.min())); x_hi.append(int(xs.max() + 1))
        y_lo.append(int(ys.min())); y_hi.append(int(ys.max() + 1))
    # Keep every icon inside the frame even when it sits on unknown ground (a
    # frontier by definition borders it, and worldToMapValidated clips strays to
    # the edge rather than dropping them).
    for _, px, py, _, _ in pending:
        x_lo.append(px - 2); x_hi.append(px + 2)
        y_lo.append(py - 2); y_hi.append(py + 2)
    cx0, cy0 = 0, 0
    if x_lo:
        h_full, w_full = costmap_image.shape[:2]
        pad = CROP_MARGIN_CELLS
        cx0, cx1 = min(x_lo) - pad, max(x_hi) + pad
        cy0, cy1 = min(y_lo) - pad, max(y_hi) + pad

        # Grow a thin box out to CROP_MIN_CELLS rather than abandoning the crop:
        # early in a run the mapped strip is only a few cells tall, and falling
        # back to the full canvas is the case the crop exists to avoid.
        def _widen(lo, hi, limit):
            short = CROP_MIN_CELLS - (hi - lo)
            if short > 0:
                lo -= short // 2
                hi += short - short // 2
            if lo < 0:
                hi, lo = hi - lo, 0
            if hi > limit:
                lo, hi = max(0, lo - (hi - limit)), limit
            return lo, hi

        cx0, cx1 = _widen(cx0, cx1, w_full)
        cy0, cy1 = _widen(cy0, cy1, h_full)
        if cx1 > cx0 and cy1 > cy0:
            costmap_image = costmap_image[cy0:cy1, cx0:cx1]

    ch, cw = costmap_image.shape[:2]
    out_scale = MAP_OUTPUT_PX / max(ch, cw, 1)
    out_scale = min(out_scale, MAP_MAX_UPSCALE)
    if out_scale != 1.0:
        costmap_image = cv2.resize(
            costmap_image,
            (max(1, int(round(cw * out_scale))), max(1, int(round(ch * out_scale)))),
            interpolation=cv2.INTER_NEAREST)

    # Now stamp the icons, in final image pixels. One conversion for the whole
    # batch rather than two per icon.
    label_boxes = []
    costmap_image = cv2.cvtColor(costmap_image, cv2.COLOR_BGR2RGBA)
    for icon_path, px, py, icon_px, text in pending:
        fx = int(round((px - cx0) * out_scale))
        fy = int(round((py - cy0) * out_scale))
        costmap_image = insert_image(
            costmap_image, icon_path, position=(fx, fy),
            size=(icon_px, icon_px),
            label_text=text,
            label_size=LABEL_FONT_SIZE,
            label_thickness=LABEL_THICKNESS,
            label_boxes=label_boxes)
    costmap_image = cv2.cvtColor(costmap_image, cv2.COLOR_RGBA2BGR)

    # Add border with cardinal directions
    # Instead of overlapping the map, create a new larger image
    height, width = costmap_image.shape[:2]
    bordered_image = np.ones((height + 2*BORDER_WIDTH, width + 2*BORDER_WIDTH, 3), dtype=np.uint8) * 200  # Light gray border
    
    # Place the original image in the center
    bordered_image[BORDER_WIDTH:BORDER_WIDTH+height, BORDER_WIDTH:BORDER_WIDTH+width] = costmap_image
    
    # Add cardinal directions
    font = cv2.FONT_HERSHEY_SIMPLEX
    font_scale = 1.0
    font_thickness = 2
    font_color = (0, 0, 0)  # Black text

    for text, (tx, ty) in (
        ("N", ((width + 2*BORDER_WIDTH) // 2, BORDER_WIDTH // 2)),
        ("S", ((width + 2*BORDER_WIDTH) // 2, height + BORDER_WIDTH + BORDER_WIDTH // 2)),
        ("E", (width + BORDER_WIDTH + BORDER_WIDTH // 2, (height + 2*BORDER_WIDTH) // 2)),
        ("W", (BORDER_WIDTH // 2, (height + 2*BORDER_WIDTH) // 2)),
    ):
        ts = cv2.getTextSize(text, font, font_scale, font_thickness)[0]
        cv2.putText(bordered_image, text, (tx - ts[0]//2, ty + ts[1]//2),
                    font, font_scale, font_color, font_thickness)

    # Add a border line to separate the map from the border area
    # Top border
    cv2.line(bordered_image, (BORDER_WIDTH-1, BORDER_WIDTH-1), (width+BORDER_WIDTH+1, BORDER_WIDTH-1), (100, 100, 100), 2)
    # Bottom border
    cv2.line(bordered_image, (BORDER_WIDTH-1, height+BORDER_WIDTH+1), (width+BORDER_WIDTH+1, height+BORDER_WIDTH+1), (100, 100, 100), 2)
    # Left border
    cv2.line(bordered_image, (BORDER_WIDTH-1, BORDER_WIDTH-1), (BORDER_WIDTH-1, height+BORDER_WIDTH+1), (100, 100, 100), 2)
    # Right border
    cv2.line(bordered_image, (width+BORDER_WIDTH+1, BORDER_WIDTH-1), (width+BORDER_WIDTH+1, height+BORDER_WIDTH+1), (100, 100, 100), 2)
    
    return bordered_image, keypoints_dict

if __name__ == '__main__':
    with open('/home/user/colcon_ws/data/frontier_detection/vis_inputs.pkl', 'rb') as f:
        costmap, frontier_dict, landmark_dict, robot_pose = pickle.load(f)
    costmap_image, keypoints_dict = vis_landmarks(costmap, frontier_dict, landmark_dict, robot_pose)
    # show the image in matplotlib
    import matplotlib.pyplot as plt
    plt.imshow(cv2.cvtColor(costmap_image, cv2.COLOR_BGR2RGB))
    plt.show()