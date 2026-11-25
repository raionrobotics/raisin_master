#!/usr/bin/env python3

import json
from collections import deque
import math
import re
import os

import numpy as np
import threading
import time

import cv2
import ast
import rclpy
from cv_bridge import CvBridge
from geometry_msgs.msg import Pose, Polygon, Point32
from mm_dev.common.tf_utils import *
from mm_dev.common.vlm_utils import VLMClient
from mm_dev.common.vis_utils import vis_landmarks, xyyaw_to_marker
from mm_dev.common.vlm_prompts import VLMPrompts
from mm_dev.common.config_loader import VLMNavConfig
import mm_dev.common.nav_utils as nav_utils_module
from mm_dev.common.nav_utils import LETHAL_COST
from mm_dev.common.nav_utils import (spin_wait, attach_pose_source,
                                     recently_abandoned)
from mm_dev.common.landmark_database import LandmarkDatabase
from mm_dev.common.frontier_utils import get_frontiers_with_filtering
from mm_dev.common.geometry_utils import quaternion_to_yaw
from landmark_handlers import LandmarkHandlers
from mm_dev.common.ablation_utils import choose_landmark_with_ablation, prepare_landmarks_dict_for_vlm
from nav2_msgs.msg import Costmap
from nav2_simple_commander.robot_navigator import BasicNavigator
from rclpy.node import Node
from rclpy.qos import QoSReliabilityPolicy, qos_profile_sensor_data
from sensor_msgs.msg import Image, JointState
from std_msgs.msg import String, Float32MultiArray
from tf2_ros import Buffer, TransformListener
from tf2_msgs.msg import TFMessage
from visualization_msgs.msg import Marker, MarkerArray
from vision_msgs.msg import Detection2DArray, ObjectHypothesisWithPose
from rclpy.callback_groups import MutuallyExclusiveCallbackGroup
try:
    from hri import HRIAgent
except (ImportError, OSError):
    # HRIAgent pulls in sounddevice/gtts (PortAudio). The handheld rig has no
    # mic or speaker, so degrade to a stub instead of failing to import.
    #
    # It must stay non-fatal at runtime: the goal already comes from
    # task.goal, but handle_person_landmark() also calls initiate() to ask a
    # detected human for directions. Raising there kills the whole node the
    # moment the VLM picks a person, so skip the conversation and carry on
    # with no extra info.
    class HRIAgent:
        _WARNED = False

        def __init__(self, *args, **kwargs):
            self.goal = None

        def get_goal(self):
            return self.goal

        def _warn(self):
            if not HRIAgent._WARNED:
                print('[hri] No audio stack: skipping spoken dialogue. '
                      'The goal comes from task.goal in vlm_nav_config.yaml.')
                HRIAgent._WARNED = True

        def initiate(self, *args, **kwargs):
            self._warn()

        def get_new_info(self):
            self._warn()
            return ''
from nav_msgs.msg import OccupancyGrid

# Load configuration
config = VLMNavConfig()

FREQ_10HZ = 0.1

# Minimum seconds per pass of the main navigation loop.
#
# With a VLM in the loop the API round-trip (1-8 s) paced it for free. The
# no-VLM ablations (modes 3/4) removed that wait, so the loop spun flat out --
# re-running frontier extraction and the 1600x1600 vis_landmarks render as fast
# as the CPU allowed, which starved the camera driver and the detector. This is
# a floor, not a delay: a pass that already took longer sleeps not at all.
LOOP_MIN_PERIOD = float(os.environ.get('REASONNAV_LOOP_PERIOD', '2.0'))

# How often to re-render /frontier_image, independent of the main loop.
# A render measures ~80 ms on the full 120 m grid, so 5 Hz is comfortable.
LANDMARK_MAP_PERIOD = float(os.environ.get('REASONNAV_MAP_PERIOD', '0.5'))
# How many landmarks a single VLM answer may plan ahead (first + queued).
PLAN_MAX = int(os.environ.get('REASONNAV_PLAN_MAX', '3'))
# A planned frontier is matched to the freshly detected one within this radius;
# frontiers are renumbered every pass so the name alone means nothing.
PLAN_FRONTIER_MATCH_M = float(os.environ.get('REASONNAV_PLAN_MATCH_M', '2.0'))
# How often the frontier set itself is recomputed from the live costmap. The
# main loop only does it once per landmark decision (5-30 s), which is why the
# red arrows lagged the map: the costmap refreshed at 2 Hz and the frontiers
# stayed where they were until the next VLM query. ~40 ms per pass.
FRONTIER_REFRESH_PERIOD = float(os.environ.get('REASONNAV_FRONTIER_PERIOD', '1.0'))
FRONTIER_REUSE_S = float(os.environ.get('REASONNAV_FRONTIER_REUSE_S', '3.0'))

# Longest side of the published /frontier_image, in pixels. 1200 px is ~4 MB a
# frame, which sustains 5 Hz; the raw render is 2460 px / 18 MB and does not.
LANDMARK_MAP_MAX_PX = int(os.environ.get('REASONNAV_MAP_MAX_PX', '1800'))
# How many sign photos ride along with the map on a choose-landmark query, and
# how large each is sent. Both are pure cost knobs.
SIGN_VIEW_LIMIT = int(os.environ.get('REASONNAV_SIGN_VIEWS', '3'))
# Direction of travel = from the point ~TRAVEL_BACK_M back along the rig's own
# path to where it stands now; the heading is only a fallback (the carrier
# turns to look at doors, the corridor does not turn with them).
TRAVEL_BACK_M = float(os.environ.get('REASONNAV_TRAVEL_BACK_M', '3.0'))
TRAVEL_STALE_S = float(os.environ.get('REASONNAV_TRAVEL_STALE_S', '45'))
# Corridor rule: while walking a corridor a sign sent us into (or the read
# numbers say the target is further on), a pick more than this far behind is
# refused as long as anything unvisited lies ahead.
CORRIDOR_BACK_M = float(os.environ.get('REASONNAV_CORRIDOR_BACK_M', '3.0'))
CORRIDOR_REASKS = int(os.environ.get('REASONNAV_CORRIDOR_REASKS', '2'))
SIGN_VIEW_MAX_PX = int(os.environ.get('REASONNAV_SIGN_VIEW_PX', '768'))

# Reading room numbers off labels caught in passing. The area gate keeps the
# OCR budget on labels big enough on the sensor to actually hold a number; the
# retry cap stops an illegible one being asked about forever.
ROOM_LABEL_MIN_PX = int(os.environ.get('REASONNAV_ROOM_LABEL_MIN_PX', '900'))
ROOM_LABEL_TRIES = int(os.environ.get('REASONNAV_ROOM_LABEL_TRIES', '5'))
ROOM_LABEL_UPSCALE_TO = int(os.environ.get('REASONNAV_ROOM_LABEL_UPSCALE', '480'))
ROOM_LABEL_DOOR_RADIUS = float(os.environ.get('REASONNAV_ROOM_LABEL_RADIUS', '4.0'))
ROOM_LABEL_PERIOD = float(os.environ.get('REASONNAV_ROOM_LABEL_PERIOD', '0.5'))   # just tops up the pool
OCR_WORKERS = int(os.environ.get('REASONNAV_OCR_WORKERS', '3'))
# Directional signs are read once each (label ranges + arrow) by the OCR model
# and the result is handed to the chooser VLM as text beside the photo, so the
# reasoning about which opening to take stays with the VLM but no longer
# depends on it re-reading small print in a downscaled photo every pass.
SIGN_READ_PERIOD = float(os.environ.get('REASONNAV_SIGN_READ_PERIOD', '2.0'))
SIGN_READ_TRIES = int(os.environ.get('REASONNAV_SIGN_READ_TRIES', '3'))
# A sign is decisive, so it is not read from far away: crops shorter than
# SIGN_MIN_H_PX are not sent to OCR, a reading only becomes final from a crop
# taller than SIGN_FINAL_H_PX, and an unread sign within SIGN_APPROACH_M is
# walked up to before anything else.
SIGN_MIN_H_PX = int(os.environ.get('REASONNAV_SIGN_MIN_H', '32'))
SIGN_FINAL_H_PX = int(os.environ.get('REASONNAV_SIGN_FINAL_H', '40'))
SIGN_APPROACH_M = float(os.environ.get('REASONNAV_SIGN_APPROACH_M', '15.0'))
# A look at least this much bigger (in area) than the one that was read
# re-opens the OCR even for a 'final' sign, and its reading REPLACES the old:
# "T131-T150" read as "T151-T150" from 6 m, correct from 1.5 m.
SIGN_RELOOK_RATIO = float(os.environ.get('REASONNAV_SIGN_RELOOK_RATIO', '2.5'))
# Reading gates. The plate has to be close and big enough that its LAST digit
# survives the crop: "T132" read from 6 m came back as "T13", got attached to
# the door and locked in, and navigation followed a room that does not exist.
ROOM_LABEL_MAX_DIST = float(os.environ.get('REASONNAV_ROOM_LABEL_MAX_DIST', '8.0'))   # sanity only: plate depth is unreliable (glossy), height gates the rest   # m
ROOM_LABEL_MIN_H_PX = int(os.environ.get('REASONNAV_ROOM_LABEL_MIN_H', '16'))   # small plates are upscaled; two agreeing reads or one confident one accept
ROOM_LABEL_MIN_CONF = float(os.environ.get('REASONNAV_ROOM_LABEL_MIN_CONF', '0.8'))   # misreads (T145 for T135, T132 for T147) came in at 0.6-0.7; true reads mostly 0.9+
# A reading is final only when it was this confident; otherwise a later, bigger
# look at the same plate re-reads it and may override.
ROOM_LABEL_FINAL_CONF = float(os.environ.get('REASONNAV_ROOM_LABEL_FINAL_CONF', '0.85'))
# A final room-label reading is re-read (at most twice) when the plate is
# seen this many times bigger (in pixel area) than it was read from.
ROOM_RELOOK_RATIO = float(os.environ.get('REASONNAV_ROOM_RELOOK_RATIO', '2.0'))
# A reading below ROOM_LABEL_MIN_CONF is still accepted if the SAME string
# comes back twice at or above this -- small far plates read consistently but
# never confidently, and waiting for a close look is exactly the delay to cut.
ROOM_LABEL_AGREE_CONF = float(os.environ.get('REASONNAV_ROOM_LABEL_AGREE_CONF', '0.5'))
# Detector score below which a room-label box is not worth an OCR call.
ROOM_LABEL_MIN_SCORE = float(os.environ.get('REASONNAV_ROOM_LABEL_MIN_SCORE', '0.45'))
# Every OCR'd plate crop is written here with its reading, so a suspicious
# number (was that T134 really T145?) can be checked against the pixels.
ROOM_READ_DIR = os.environ.get('REASONNAV_ROOM_READ_DIR',
                               os.path.expanduser('~/tips_ws/logs/room_reads'))

pts = config.get('navigation.footprint')
FOOTPRINT_POLYGON = Polygon(points=[Point32(x=pt[0], y=pt[1]) for pt in pts])
UPDATE_THRESHOLD = config.get('navigation.update_threshold')
ROBOT_LENGTH = config.get('navigation.robot_length')
MAX_REPOSITION_ATTEMPTS = config.get('navigation.max_reposition_attempts')

# Ablation mode configuration
ABLATION = config.get('ablation.mode')
if ABLATION == 2:
    DEFAULT_DET_QUERY = config.get('ablation.no_info_detection.query')
    DEFAULT_DET_THRESH = config.get('ablation.no_info_detection.threshold')
else:
    DEFAULT_DET_QUERY = config.get('detection.default_query')
    DEFAULT_DET_THRESH = config.get('detection.default_threshold')

VLM_SIGN_DIR = config.get('vlm.use_vlm_for_sign_direction')
# The target room. Config holds the default; the environment wins so a run can
# be aimed from the launch command instead of by editing yaml. Kept as a string
# because this building numbers rooms T106, T131 -- see _is_goal.
GOAL = str(os.environ.get('REASONNAV_GOAL') or config.get('task.goal')).strip()


def _target_number(target):
    """'Room T145' -> ('T', 145); None if there is no number."""
    m = re.search(r'([A-Za-z]*)\s*(\d+)', str(target))
    return (m.group(1).upper(), int(m.group(2))) if m else None


def _parse_label_range(label):
    """'T131-T150' / 'T131~150' / 'T145' -> ('T', 131, 150); None if not a number."""
    m = re.match(r'\s*([A-Za-z]*)\s*(\d+)\s*(?:[-~\u2013\u2014]+|to)\s*([A-Za-z]*)\s*(\d+)\s*$', str(label))
    if m:
        lo, hi = int(m.group(2)), int(m.group(4))
        return (m.group(1).upper(), min(lo, hi), max(lo, hi))
    m = re.match(r'\s*([A-Za-z]*)\s*(\d+)\s*$', str(label))
    if m:
        n = int(m.group(2))
        return (m.group(1).upper(), n, n)
    return None


def _range_has(rng, tgt):
    prefix, lo, hi = rng
    return (prefix == tgt[0] or not prefix or not tgt[0]) and lo <= tgt[1] <= hi


def _parse_sign_entries(raw):
    """Pull the JSON list out of an OCR reply; normalise arrows."""
    if raw is None:
        return None
    txt = str(raw)
    i, j = txt.find('['), txt.rfind(']')
    if i < 0 or j <= i:
        return None
    try:
        data = json.loads(txt[i:j + 1])
    except ValueError:
        return None
    out = []
    for e in data if isinstance(data, list) else []:
        if not isinstance(e, dict):
            continue
        arrow = str(e.get('arrow', 'none')).strip().lower()
        arrow = {'straight': 'up', 'forward': 'up', 'ahead': 'up', 'back': 'down',
                 'backward': 'down', 'backwards': 'down'}.get(arrow, arrow)
        if arrow not in ('left', 'right', 'up', 'down', 'none'):
            arrow = 'none'
        label = str(e.get('label', '')).strip()
        # A range printed high-to-low does not exist; "T151-T150" was a 3
        # misread as 5 on a small crop. Drop it so the sign is read again.
        m = re.match(r'\s*([A-Za-z]*)\s*(\d+)\s*(?:[-~\u2013\u2014]+|to)\s*([A-Za-z]*)\s*(\d+)\s*$', label)
        if m and int(m.group(2)) > int(m.group(4)):
            continue
        out.append({'label': label, 'arrow': arrow})
    return out


def _compass8(deg):
    """Map bearing -> the border label the landmark map uses.

    The map's border says N at +x, W at +y, S at -x, E at -y (the image is the
    costmap transposed and flipped), so bearings run N -> W -> S -> E going
    counter-clockwise, not the clockwise compass a person expects.
    """
    names = ['N', 'NW', 'W', 'SW', 'S', 'SE', 'E', 'NE']
    return names[int(((deg % 360.0) + 22.5) // 45.0) % 8]


def _ang_diff(a, b):
    return ((a - b + 180.0) % 360.0) - 180.0


class _TeeLogger:
    """Forward to the rclpy logger and append the same line to a text file,
    so a run can be read back without scraping ~/.ros/log or the terminal."""
    def __init__(self, real, path):
        self._real = real
        self._fh = open(path, 'a', buffering=1)
    def _w(self, lvl, msg):
        try:
            self._fh.write(f"{time.strftime('%H:%M:%S')} {lvl} {msg}\n")
        except Exception:
            pass
    def debug(self, msg, **kw): return self._real.debug(msg, **kw)
    def info(self, msg, **kw):  self._w('I', msg); return self._real.info(msg, **kw)
    def warn(self, msg, **kw):  self._w('W', msg); return self._real.warn(msg, **kw)
    def warning(self, msg, **kw): return self.warn(msg, **kw)
    def error(self, msg, **kw): self._w('E', msg); return self._real.error(msg, **kw)
    def fatal(self, msg, **kw): self._w('F', msg); return self._real.fatal(msg, **kw)
    def __getattr__(self, name): return getattr(self._real, name)


RUN_LOG_DIR = os.environ.get('REASONNAV_RUN_LOG_DIR', os.path.expanduser('~/tips_ws/logs/runs'))


class VLMNav(Node):
    """VLM-based navigation node for indoor wayfinding.

    Uses vision-language models to reason about navigation strategy,
    combining object detection, frontier exploration, and human interaction
    to find target rooms in indoor environments.
    """

    def __init__(self):
        super().__init__('VLMNav_node')
        # Every log line also goes to logs/runs/<start time>_vlm_nav.log.
        try:
            os.makedirs(RUN_LOG_DIR, exist_ok=True)
            self._run_log_path = os.path.join(RUN_LOG_DIR, time.strftime('%Y%m%d_%H%M%S') + '_vlm_nav.log')
            self._tee = _TeeLogger(super().get_logger(), self._run_log_path)
        except Exception:
            self._tee = None

        # Initialize Nav2 Simple Commander
        self.get_logger().info("Nav2 Commander Node is running...")
        self.tf_buffer = Buffer()
        self.tf_listener = TransformListener(self.tf_buffer, self)
        # pose_update runs from the spin_once loop just below, i.e. BEFORE the
        # rest of __init__ -- anything it touches must already exist here.
        # (monotonic t, x, y) at the pose_update rate; see _travel_axis.
        self._trail = deque(maxlen=1200)
        self._corridor = None
        self._corridor_rejects = 0
        self._door_conf = {}          # door index -> (reading, conf, h_px) of the label it carries
        self._door_votes = {}         # door index -> {reading: count} for one-digit-different rereads
        self.create_timer(FREQ_10HZ, self.pose_update)
        self.robot_pose:Pose = None # in map frame
        while self.robot_pose is None:
            rclpy.spin_once(self)
            time.sleep(0.1)
        self.get_logger().info("Robot pose initialized")
        self.exclusive_group = MutuallyExclusiveCallbackGroup()
        self.detection_sub = self.create_subscription(
            Detection2DArray, 
            '/object_detector/output_detections',
            self.detection_callback,
            qos_profile=10,
            callback_group=self.exclusive_group
        )
        self.det_query_pub = self.create_publisher(String, '/object_detector/input_query', 10)
        self.det_thresh_pub = self.create_publisher(Float32MultiArray, '/object_detector/threshold', 10)
        # Set up QoS profile
        modified_qos = qos_profile_sensor_data
        modified_qos.reliability = QoSReliabilityPolicy.BEST_EFFORT

        self.cv_bridge = CvBridge()
        self.realsense_sub = self.create_subscription(
            Image,
            '/camera/color/image_raw',
            self.realsense_callback,
            qos_profile=modified_qos
        )
        self.realsense_img = None

        self.global_costmap_sub = self.create_subscription(
            OccupancyGrid,
            '/global_costmap/costmap',
            self.costmap_callback,
            10
        )
        
        self.pan_tilt_pub = self.create_publisher(JointState, '/pan_tilt/joint_command', 10)
        self.joint_state_sub = self.create_subscription(JointState, '/joint_states', self.joint_state_callback, 10)
        self.pan_joint_state = None
        self.vlm_text_pub = self.create_publisher(String, 'vlm_text', 10)
        self.landmark_vis_pub = self.create_publisher(TFMessage, '/tf', 10)
        self.goal_marker_pub = self.create_publisher(Marker, 'goal_marker', 10)
        self.marker_pub = self.create_publisher(MarkerArray, 'frontiers', 10)
        self.frontier_image_pub = self.create_publisher(Image, 'frontier_image', 10)
        self.costmap = None

        # The landmark map used to be rendered once per pass of the main loop,
        # which meant it froze for as long as a landmark handler ran -- an
        # approach plus a VLM OCR easily blocks for a minute, and nothing was
        # published before the first pass completed either. Render it on its own
        # timer instead, from the latest costmap/pose/landmarks, so the picture
        # you steer by keeps updating no matter what the loop is doing.
        self.last_frontier_dict = {}
        # Best camera view of each directional sign, keyed by its landmark
        # index: {'img', 'score', 'area', 'robot_xy'}. The chooser hands these
        # to the VLM alongside the map so it can read the arrow itself instead
        # of trusting a cardinal string distilled out of it -- see
        # SIGN_VIEW_LIMIT and choose_next_landmark_prompt.
        self.sign_views = {}
        # Room labels seen in passing, keyed by landmark index:
        # {'crop', 'area', 'pose', 'tries'}. Read by a timer rather than here,
        # because OCR is a network round trip and this callback shares its
        # thread with the pose update and the map render.
        self.room_labels = {}
        self.room_lock = threading.Lock()
        self._room_skip_logged = set()
        # Plate OCR runs on its own small pool; see _read_room_labels.
        from concurrent.futures import ThreadPoolExecutor
        self._ocr_pool = ThreadPoolExecutor(max_workers=OCR_WORKERS, thread_name_prefix='ocr')
        self._ocr_inflight = set()
        self.frames = deque(maxlen=45)
        # The camera callback appends while the detection callback reads, on
        # different executor threads; iterating a deque mid-append raises and
        # the exception takes the whole executor down with it.
        self.frames_lock = threading.Lock()
        # Set when a room number read in passing matches the goal; the main
        # loop watches it so the mission can end without having to walk up to
        # the door and inspect it deliberately.
        self.goal_reached = False
        # Landmarks the VLM said to visit after the current one, in order.
        self.plan_queue = []
        self._plan_sign_sig = None
        self._map_stats = []
        self._map_stats_t0 = time.perf_counter()
        # Its own callback group: the default one is mutually exclusive, so the
        # render would queue behind pose_update (10 Hz) and the camera callback
        # and miss its period.
        # Its own group: an OCR round trip must not hold up the pose update or
        # the map render, and only one may be in flight at a time.
        self.create_timer(SIGN_READ_PERIOD, self._read_signs,
                          callback_group=MutuallyExclusiveCallbackGroup())
        self.create_timer(ROOM_LABEL_PERIOD, self._read_room_labels,
                          callback_group=MutuallyExclusiveCallbackGroup())
        self.create_timer(FRONTIER_REFRESH_PERIOD, self.refresh_frontiers,
                          callback_group=MutuallyExclusiveCallbackGroup())
        self.create_timer(LANDMARK_MAP_PERIOD, self.publish_landmark_map,
                          callback_group=MutuallyExclusiveCallbackGroup())

        self.vlm_text_pub = self.create_publisher(String, '/vlm_text', 10)
        self.landmark_json_pub = self.create_publisher(String, '/landmark_json', 10)

        # Memory Data Structures
        self.goal = None
        self.landmark_db = LandmarkDatabase(self)
        # The config knob was read into UPDATE_THRESHOLD and then never applied,
        # so the database silently kept its own hardcoded 1.5 m. This is the
        # radius within which a new detection counts as the SAME landmark, so a
        # dead knob here means duplicate doors cannot be tuned away.
        if UPDATE_THRESHOLD:
            self.landmark_db.update_threshold = float(UPDATE_THRESHOLD)
        self.frontiers = []

        # Detection defaults for landmark_handlers
        self.default_det_query = DEFAULT_DET_QUERY
        self.default_det_thresh = DEFAULT_DET_THRESH

        # Agents
        self.vlm_client = VLMClient(model=config.get('vlm.model'))
        # Reading text off a sign is the accuracy-critical job and runs once per
        # door, so it does not have to share the fast model the per-loop
        # landmark choice uses.
        self.ocr_client = VLMClient(
            model=config.get('vlm.ocr_model') or config.get('vlm.model'))
        self.hri_agent = HRIAgent()
        self.landmark_handlers = LandmarkHandlers(self)

    def get_logger(self):
        t = getattr(self, '_tee', None)
        return t if t is not None else super().get_logger()

    def costmap_callback(self, msg: Costmap):
        self.costmap = msg

    def pose_update(self):
        to_frame_rel = 'map'
        from_frame_rel = 'base_link'
        robot_tf = get_tf(to_frame_rel, from_frame_rel, rclpy.time.Time(), self.tf_buffer)
        if robot_tf is None:
            return
        self.robot_pose = transform_msg_to_pose_msg(robot_tf)
        x, y, _ = pose_msg_to_xyyaw(self.robot_pose)
        self._trail.append((time.monotonic(), x, y))

    def _travel_axis(self):
        """Unit vector of the direction of travel, plus whether the rig has
        actually moved. From the point TRAVEL_BACK_M back along the walked path
        to the current position; the heading only when it has not moved that
        far within TRAVEL_STALE_S. Returns (ux, uy, moving) or None."""
        if self.robot_pose is None:
            return None
        rx, ry, ryaw = pose_msg_to_xyyaw(self.robot_pose)
        now = time.monotonic()
        for t, x, y in reversed(self._trail):
            if now - t > TRAVEL_STALE_S:
                break
            d = math.hypot(rx - x, ry - y)
            if d >= TRAVEL_BACK_M:
                return ((rx - x) / d, (ry - y) / d, True)
        return (math.cos(ryaw), math.sin(ryaw), False)

    def _forward_waypoint(self, frontier_dict, landmarks_dict):
        """A waypoint a few metres down the corridor when nothing else is ahead.

        Mid-corridor the frontier at the far end is often not on the map yet
        (unknown cells too far, gap filter, or a 20 s stall abandoned it) and
        every remaining landmark is behind. The VLM then picked the exit --
        a person just keeps walking. Returns (x, y, yaw) on free, known ground
        along the corridor axis, or None.
        """
        cor = self._corridor
        if not cor or not (cor.get('followed_sign') or cor.get('predict') == 'ahead') or self.robot_pose is None:
            return None
        rx, ry, _ = pose_msg_to_xyyaw(self.robot_pose)
        ux, uy = cor['ux'], cor['uy']
        cands = [('Frontier', v) for v in frontier_dict.values()] + list(landmarks_dict.items())
        for name, v in cands:
            if not isinstance(v, dict):
                continue
            pos = v.get('position_xy') or v.get('position')
            # Only what the VLM can actually be sent to: doors and frontiers.
            # Room-label landmarks are in this dict too (the plate ahead is
            # always "unvisited"), and counting them meant no waypoint was
            # ever offered.
            nm = str(name)
            if pos is None or nm.startswith('Visited_') or not (nm.startswith('Frontier') or 'door' in nm):
                continue
            along = (pos[0] - rx) * ux + (pos[1] - ry) * uy
            # Something unvisited within reach ahead: no waypoint needed. A
            # frontier 45 m ahead does not count -- when the numbers put the
            # target 3 m behind us and FORWARD has turned round, the far end
            # of the corridor is "ahead" too, and the VLM walked 45 m to it
            # instead of turning to look 3 m away.
            est0 = cor.get('est')
            limit = 20.0 if est0 is None else min(20.0, est0 + 4.0)
            if 1.0 < along <= limit:
                self.get_logger().debug(f'corridor: {nm} {along:.0f} m ahead -- no waypoint needed')
                return None
        grid = self.costmap
        info = getattr(grid, 'info', None)
        if info is None or not grid.data:
            return None
        data = np.asarray(grid.data, dtype=np.int16).reshape(info.height, info.width)
        res = info.resolution
        r = max(1, int(round(0.3 / res)))
        lx, ly = -uy, ux
        # Where the numbers put the target, if they do; else as far as 8 m.
        est = cor.get('est')
        far = 8.0 if est is None else float(min(8.0, max(3.0, est)))
        # Straight ahead first; then a little to either side, because the
        # carrier tends to walk along one wall and the line through them can
        # graze the inflated band.
        for d in np.arange(far, 2.9, -0.5):
            for off in (0.0, 0.5, -0.5, 1.0, -1.0):
                px, py = rx + d * ux + off * lx, ry + d * uy + off * ly
                ix = int((px - info.origin.position.x) / res); iy = int((py - info.origin.position.y) / res)
                if not (r <= ix < info.width - r and r <= iy < info.height - r):
                    continue
                patch = data[iy - r:iy + r + 1, ix - r:ix + r + 1]
                if (patch < 0).any() or (patch >= LETHAL_COST).any():
                    continue
                return (float(px), float(py), math.atan2(uy, ux))
        self.get_logger().info('corridor: nothing unvisited ahead and no known free ground 3-8 m ahead either')
        return None

    def _axis_from_map(self, px, py, cap=25.0):
        """Corridor direction at (px, py) from the costmap, or None.

        Rays are cast every 5 degrees from the nearest point of the walked
        path (known free) and the free run measured both ways; a corridor is
        the direction whose two runs together are longest and clearly longer
        than the runs at right angles to it. In a lobby the runs are alike
        in every direction and None is returned.
        """
        grid = self.costmap
        info = getattr(grid, 'info', None)
        if info is None or not grid.data or not self._trail:
            return None
        ox, oy = min(((x, y) for _, x, y in self._trail), key=lambda q: math.hypot(q[0] - px, q[1] - py))
        if math.hypot(ox - px, oy - py) > 4.0:
            return None
        data = np.asarray(grid.data, dtype=np.int16).reshape(info.height, info.width)
        res = info.resolution
        step = max(res, 0.1)

        def run(dx, dy):
            d = step
            while d < cap:
                ix = int((ox + d * dx - info.origin.position.x) / res)
                iy = int((oy + d * dy - info.origin.position.y) / res)
                if not (0 <= ix < info.width and 0 <= iy < info.height):
                    break
                c = data[iy, ix]
                if c < 0 or c >= LETHAL_COST:
                    break
                d += step
            return d

        runs = {}
        for deg in range(0, 180, 5):
            a = math.radians(deg)
            dx, dy = math.cos(a), math.sin(a)
            runs[deg] = run(dx, dy) + run(-dx, -dy)
        best = max(runs, key=runs.get)
        perp = runs[(best + 90) % 180]
        if runs[best] < 5.0 or runs[best] < 1.8 * perp:
            return None
        a = math.radians(best)
        return (math.cos(a), math.sin(a))

    def _ahead_in_corridor(self, x, y):
        """True if (x, y) lies ahead along the corridor being walked.

        Used to keep the corridor's far-end frontier on the table even after a
        "no progress for 20 s" abandonment: the carrier stopping to read a
        plate is not the frontier being unreachable, and dropping it left the
        VLM with nothing but the exits behind.
        """
        cor = self._corridor
        if not cor or not (cor.get('followed_sign') or cor.get('predict') == 'ahead') or self.robot_pose is None:
            return False
        rx, ry, _ = pose_msg_to_xyyaw(self.robot_pose)
        return (x - rx) * cor['ux'] + (y - ry) * cor['uy'] > 3.0

    def _in_range_read_exists(self, ranges):
        db = self.landmark_db.landmark_db.get('a door')
        if not db:
            return False
        for lab in db.get('labels', []):
            r = _parse_label_range(lab) if lab else None
            if r and r[1] == r[2] and any(_range_has(rr, (r[0], r[1])) for rr in ranges):
                return True
        return False

    def _valid_reads(self, keypoints_dict, target, exclude_other=True):
        """Room numbers fit to carry a numbering trend: same prefix and digit
        count as the target, and inside a sign range covering the target once
        one has been read. Returns [(x, y, number, room, key)].

        A plate cut by the frame edge reads "T34" for T134 and "T45" for T145
        with confidence 0.9; one such read flipped the fitted direction of the
        run and sent the carrier back out of the corridor.
        """
        tgt = _target_number(target)
        if not tgt:
            return []
        ranges, other = [], []
        for v in self.sign_views.values():
            for e in (v.get('entries') or []):
                r = _parse_label_range(e['label'])
                if r and r[1] != r[2]:
                    (ranges if _range_has(r, tgt) else other).append(r)
        out = []
        for k, v in keypoints_dict.items():
            room = v.get('room') if isinstance(v, dict) else None
            if not room or 'position' not in v:
                continue
            r = _parse_label_range(room)
            if r is None or r[1] != r[2]:
                continue
            prefix, n = r[0], r[1]
            if tgt[0] and prefix and prefix != tgt[0]:
                continue
            if len(str(n)) != len(str(tgt[1])):
                continue
            # For the TREND only: keep reads inside a range covering the target
            # (once such a sign exists) and drop reads inside a range that
            # excludes it -- those were read in the wrong corridor, and mixed
            # in (T101, T102, T103 ... T132) they turned the trend round and
            # sent the rig 25 m back towards T132. The ruled-out computation
            # asks with exclude_other=False and needs exactly those reads.
            if exclude_other:
                if ranges and not any(_range_has(rr, (prefix, n)) for rr in ranges):
                    continue
                if any(_range_has(rr, (prefix, n)) for rr in other):
                    continue
            out.append((float(v['position'][0]), float(v['position'][1]), n, str(room), k))
        return out

    def _corridor_context(self, keypoints_dict, target):
        """What a person walking this corridor would hold in their head.

        The corridor's axis comes from the read door plates (their positions
        line the corridor), and FORWARD along it is the direction in which the
        numbers on the target's side run towards the target -- not the way the
        rig happens to be walking or facing. Walking back three metres to a
        missed door must not turn the far end of the corridor into "behind".
        With fewer than two usable plates the direction of travel stands in.
        Sets self._corridor for the corridor rule; returns the prompt lines.
        """
        ax = self._travel_axis()
        if ax is None:
            self._corridor = None
            return []
        ux, uy, moving = ax
        rx, ry, _ = pose_msg_to_xyyaw(self.robot_pose)
        tgt = _target_number(target)
        reads = self._valid_reads(keypoints_dict, target)
        basis = 'travel'
        # The sign that sent us in stands at the corridor mouth and the plates
        # in its range line the corridor: sign -> plate centroid is the
        # corridor axis, pointing in. Robust to which wall was read, to the
        # carrier weaving or stepping into a side branch, and to having walked
        # back past the sign. Two earlier attempts (PCA of the plates, PCA of
        # the walked path) each broke on one of those.
        sign_xy = None
        if tgt:
            sdb = self.landmark_db.landmark_db.get('a directional sign')
            for idx, view in self.sign_views.items():
                if sdb is None or idx >= len(sdb['positions']):
                    continue
                if any((r := _parse_label_range(e['label'])) and r[1] != r[2] and _range_has(r, tgt)
                       for e in (view.get('entries') or [])):
                    sign_xy = (float(sdb['positions'][idx][0]), float(sdb['positions'][idx][1]))
                    break
        if sign_xy is not None and reads:
            cx = float(np.mean([x for x, *_ in reads])); cy = float(np.mean([y for _, y, *_ in reads]))
            dx, dy = cx - sign_xy[0], cy - sign_xy[1]
            d = math.hypot(dx, dy)
            if d >= 5.0:
                ux, uy = dx / d, dy / d
                basis = 'sign'
        elif len(reads) >= 2:
            P = np.array([[x, y] for x, y, *_ in reads])
            if np.ptp(P, axis=0).max() >= 5.0:
                _, _, vt = np.linalg.svd(P - P.mean(axis=0))
                ex, ey = float(vt[0][0]), float(vt[0][1])
                if ex * ux + ey * uy < 0:
                    ex, ey = -ex, -ey          # start off pointing the way we walk
                ux, uy = ex, ey
                basis = 'plates'
        # Refine the direction: the plates sit on two parallel walls, so the
        # true axis is the one along which their sideways offsets bunch into
        # (at most) two tight groups. A few degrees of tilt puts a plate 25 m
        # away on the wrong wall, and every side-based inference after that
        # is wrong; the centroid direction above is easily that far off.
        if len(reads) >= 3 and basis != 'travel':
            def sse(th):
                cx_, sx_ = math.cos(th), math.sin(th)
                L = sorted((x - rx) * (-sx_) + (y - ry) * cx_ for x, y, *_ in reads)
                gaps = [L[i + 1] - L[i] for i in range(len(L) - 1)]
                i = int(np.argmax(gaps))
                groups = [L[:i + 1], L[i + 1:]] if gaps[i] > 1.0 else [L]
                return sum(float(np.sum((np.array(g) - np.mean(g)) ** 2)) for g in groups if g)
            th0 = math.atan2(uy, ux)
            best = min((sse(th0 + math.radians(k)), k) for k in range(-25, 26))
            th = th0 + math.radians(best[1])
            ux, uy = math.cos(th), math.sin(th)
        lx, ly = -uy, ux
        # Coordinates follow the WALKED PATH, not a straight line: "behind" is
        # the arc length back along the trail to the point nearest the
        # landmark, and left/right is judged against the trail's direction
        # there. A corridor that bends (or a walk that turned a corner) keeps
        # its doors on the right walls this way; a straight axis through the
        # rig put doors passed before the bend on the wrong side and stacked
        # their numbers into one bogus run. Things off the path (ahead, or in
        # a side branch) fall back to the straight projection from the rig.
        tpts = [(x, y) for _, x, y in self._trail]
        cum = [0.0]
        for i in range(1, len(tpts)):
            cum.append(cum[-1] + math.hypot(tpts[i][0] - tpts[i - 1][0], tpts[i][1] - tpts[i - 1][1]))
        def along_lat(px, py):
            if len(tpts) >= 8:
                j = min(range(len(tpts)), key=lambda i: (tpts[i][0] - px) ** 2 + (tpts[i][1] - py) ** 2)
                tx, ty = tpts[j]
                if math.hypot(tx - px, ty - py) < 4.0 and cum[-1] - cum[j] > 1.0:
                    # Local direction over a long window (about 4 s of walking
                    # each way): the short one took the detour towards a door
                    # as the corridor direction and put that door on the wrong
                    # wall, which then broke the numbering runs.
                    a0, b0 = max(0, j - 40), min(len(tpts) - 1, j + 40)
                    dx, dy = tpts[b0][0] - tpts[a0][0], tpts[b0][1] - tpts[a0][1]
                    n = math.hypot(dx, dy)
                    if n < 2.0:
                        dx, dy, n = ux, uy, 1.0          # too little path here: corridor axis
                    dx, dy = dx / n, dy / n
                    # Side from the path's local direction; distance along the
                    # corridor from the straight axis. Arc length was wrong the
                    # moment the walk doubled back: everything the rig had
                    # walked past, including the frontier ahead of it, became
                    # "behind" by the length of the detour.
                    return (px - rx) * ux + (py - ry) * uy, (px - tx) * (-dy) + (py - ty) * dx
            return (px - rx) * ux + (py - ry) * uy, (px - rx) * lx + (py - ry) * ly
        # Which wall a plate is on: split the plates at the widest gap between
        # their laterals when there is one (two walls), else at the walked
        # line itself.
        lat0 = 0.0
        plate_lats = sorted(along_lat(x, y)[1] for x, y, *_ in reads)
        split = lat0
        if len(plate_lats) >= 2:
            gaps = [(plate_lats[i + 1] - plate_lats[i], i) for i in range(len(plate_lats) - 1)]
            g, i = max(gaps)
            if g > 1.5:
                split = (plate_lats[i] + plate_lats[i + 1]) / 2.0
        side_of = lambda l: 'left' if l > split else 'right'
        runs = {'left': [], 'right': []}
        for x, y, n, room, k in reads:
            a, l = along_lat(x, y)
            runs[side_of(l)].append((a, n, room))
        # A number read at two doors metres apart is a misread somewhere ("T145"
        # for T135); neither copy can anchor the fit.
        byn = {}
        for x, y, n, room, k in reads:
            byn.setdefault(n, []).append((x, y))
        # The same number on two doors more than 2 m apart is a misread
        # somewhere -- including one on each wall ("T143" on both sides put
        # the target on the wrong wall and turned the rig round 2 m from it).
        dup_all = {n for n, P in byn.items()
                   if len(P) >= 2 and max(math.hypot(a[0] - b[0], a[1] - b[1]) for a in P for b in P) > 2.0}
        dup = {'left': dup_all, 'right': dup_all}
        # Which side is the target's, and which way do its numbers run?
        best_side, est, per_room = None, None, None
        self._corridor_weak = None
        if tgt:
            scored = [(min(abs(n - tgt[1]) for _, n, _ in rd), sd) for sd, rd in runs.items() if rd]
            # "Nearest the target" only means something when that side has a
            # run (two reads) or a number actually close to the target. One
            # read of T132 with target T105 produced "the RIGHT side's numbers
            # are the ones nearest Room T105", and the VLM went 22 m back into
            # the 130s corridor to follow a run that had nothing to do with it.
            if scored and (min(scored)[0] <= 10 or len(runs[min(scored)[1]]) >= 2):
                best_side = min(scored)[1]
                rd = sorted((a, n, room) for a, n, room in runs[best_side] if n not in dup[best_side])
                pairs = [((n2 - n1) / (a2 - a1)) for i, (a1, n1, _) in enumerate(rd)
                         for (a2, n2, _) in rd[i + 1:] if abs(a2 - a1) > 1.0]
                if len(pairs) >= 1:
                    # Median pairwise slope (Theil-Sen): one bad plate cannot
                    # flip it. Rooms come every 1-30 m; anything else is noise.
                    slope = float(np.median(pairs))
                    # Rooms on one wall are 2.5-30 m apart. Faster than that means
                    # two walls got mixed into one run (T145 and T132 "on the same
                    # side", 1 m per room) -- which turned the rig round mid-corridor.
                    if 1.0 / 30.0 <= abs(slope) <= 1.0 / 2.5:
                        ests = [a + (tgt[1] - n) / slope for a, n, _ in rd]
                        est = float(np.median(ests))
                        per_room = 1.0 / abs(slope)
                        # Extrapolating far beyond the numbers actually read
                        # (T101-T103 -> "T143 is 200 m ahead") says nothing
                        # about THIS corridor; treating it as a prediction
                        # would refuse the exit frontiers and march the rig
                        # down the wrong corridor to its end.
                        rooms_off = min(abs(tgt[1] - n) for _, n, _ in rd)
                        if abs(est) > 60.0 or rooms_off > 12:
                            self._corridor_weak = (est, rooms_off)
                            est = None
        flip = est is not None and est < -1.0
        if flip:
            # FORWARD is the other way.
            ux, uy, lx, ly = -ux, -uy, -lx, -ly
            if est is not None:
                est = -est
            for sd in runs:
                runs[sd] = [(-a, n, room) for a, n, room in runs[sd]]
            runs['left'], runs['right'] = runs['right'], runs['left']
            dup['left'], dup['right'] = dup['right'], dup['left']
            best_side = {'left': 'right', 'right': 'left'}.get(best_side, best_side)
            split = -split
            side_of = lambda l: 'left' if l > split else 'right'
            basis = basis + ' (turned round)'
        cand = lambda v: ((str(v['name']).startswith('Unvisited_') or str(v['name']).startswith('Frontier'))
                          and 'sign' not in str(v['name']))
        items = []
        for k, v in keypoints_dict.items():
            if 'position' not in v or 'robot' in str(v.get('name', '')) or not cand(v):
                continue
            a, l = along_lat(*v['position'][:2])
            items.append((a, l, k, v))
        ahead = sorted([t for t in items if t[0] > 1.0], key=lambda t: t[0])
        behind = sorted([t for t in items if t[0] < -1.0], key=lambda t: -t[0])
        fmt = lambda a, l, k, v: f"{v['name']} [{k}] ({abs(a):.0f} m, {side_of(l)} side)"
        if basis.startswith('plates'):
            head = ("Along the corridor the read plates line, FORWARD being the way the numbers "
                    "run towards the target" + (" -- which is BACK the way you came" if 'turned' in basis else "")
                    + ", from where you stand now:")
        elif basis.startswith('sign'):
            head = ("Along this corridor, FORWARD being deeper in, away from the sign that sent you here"
                    + (" -- which is BACK the way you came" if 'turned' in basis else "")
                    + ", from where you stand now:")
        elif moving:
            head = "Measured along the way you have been walking, from where you stand now:"
        else:
            head = "Measured along the way you are facing (you have not moved lately), from where you stand now:"
        lines = [head]
        lines.append("  AHEAD: " + (", ".join(fmt(*t) for t in ahead[:6]) if ahead else "nothing unvisited"))
        if any('Frontier_ahead' in str(v.get('name', '')) for _, _, k, v in ahead):
            if est is not None and est <= 10.0:
                lines.append("  (Frontier_ahead is the spot where the numbers put the target: go there and look for its door.)")
            else:
                lines.append("  (Frontier_ahead is simply the corridor continuing in front of you: take it to keep walking.)")
        lines.append("  BEHIND: " + (", ".join(fmt(*t) for t in behind[:4]) if behind else "nothing unvisited"))
        for sd in ('left', 'right'):
            rd = sorted(runs[sd])
            if not rd:
                continue
            txt = ", ".join((f"{room} ({-a:.0f} m back)" if a < 0 else f"{room} ({a:.0f} m ahead)")
                            + (" (read twice at different doors -- one is a misread)" if n in dup[sd] else "")
                            for a, n, room in rd)
            line = f"  {sd.upper()} side, numbers in walking order: {txt}."
            good = [t for t in rd if t[1] not in dup[sd]]
            if len(good) >= 2 and good[0][1] != good[-1][1]:
                line += f" They {'increase' if good[-1][1] > good[0][1] else 'decrease'} as you go forward."
            if sd == best_side:
                if est is not None:
                    line += f" So {target} should be about {est:.0f} m AHEAD on this side."
                elif getattr(self, '_corridor_weak', None):
                    we, wr = self._corridor_weak
                    line += (f" If this run continues it would put {target} roughly {abs(we):.0f} m "
                             f"{'ahead' if we > 0 else 'behind'} -- {wr} rooms beyond anything read here, so this "
                             f"corridor may well not hold it; leaving it is a fair choice.")
                elif len(good) >= 2:
                    line += " (too few or too spread to place the target yet -- read the next door on this side)"
                else:
                    line += " (one number only -- read the next door on this side to learn which way they run)"
            lines.append(line)
        if best_side and est is None:
            lines.append(f"  The {best_side.upper()} side's numbers are the ones nearest {target}.")
        # A sign whose range holds the numbers read here but NOT the target
        # says, in so many words, that this is the wrong corridor. Saying so
        # in the prompt was not enough: the VLM agreed the corridor was ruled
        # out and then picked its frontier anyway, "to find a different
        # corridor". So the corridor is drawn on the map -- the axis from the
        # sign through the plates read in its range -- and every door and
        # frontier inside it is named here and refused as a pick.
        self._ruled_out = None
        if tgt:
            sdb = self.landmark_db.landmark_db.get('a directional sign')
            for idx, view in self.sign_views.items():
                if sdb is None or idx >= len(sdb['positions']):
                    continue
                sx_, sy_ = float(sdb['positions'][idx][0]), float(sdb['positions'][idx][1])
                for e in (view.get('entries') or []):
                    r = _parse_label_range(e['label'])
                    if not r or r[1] == r[2] or _range_has(r, tgt):
                        continue
                    # All reads, including the ones excluded from this
                    # corridor's trend: those are exactly the plates that tell
                    # us where the ruled-out corridor is.
                    all_reads = self._valid_reads(keypoints_dict, target, exclude_other=False)
                    inside = [(x, y, room) for x, y, n, room, k in all_reads if _range_has(r, (r[0], n))]
                    if inside:
                        # Plates in the range have been read: the corridor is
                        # the one they line. Its axis is remembered the first
                        # time it is worked out (the rig is then walking along
                        # it) and only replaced by a wall-aligned fit from three
                        # or more of its plates. Recomputing it from whatever
                        # the rig was doing later put the band across a side
                        # branch and let the corridor's own frontiers through.
                        cx_ = float(np.mean([x for x, _, _ in inside])); cy_ = float(np.mean([y for _, y, _ in inside]))
                        remembered = getattr(self, '_ruled_axes', {}).get(e['label'])
                        # The corridor's own axis: the stretch of path the rig
                        # walked while passing its plates. That does not change
                        # with what the rig is doing now, and it is right even
                        # with a single plate (the walk past it was along the
                        # corridor). Remembering "the axis at first rule-out"
                        # was not: once it was computed while the rig walked
                        # up a side branch and the band missed the corridor.
                        near_pts = [(x, y) for _, x, y in self._trail
                                    if any(math.hypot(x - px_, y - py_) < 3.0 for px_, py_, _ in inside)]
                        # The map itself knows where the corridor runs: from a
                        # spot the rig stood at while reading the plate, the
                        # direction with by far the longest free run is the
                        # corridor. The walked path there is not reliable --
                        # at T132 the carrier stepped to the door and turned
                        # off north into the lobby, the axis came out diagonal
                        # and the band covered the lobby instead of the corridor.
                        map_ax = self._axis_from_map(cx_, cy_)
                        if map_ax is not None:
                            ex_, ey_ = map_ax
                            remembered = None
                        elif len(near_pts) >= 10 and np.ptp(np.array(near_pts), axis=0).max() >= 2.5:
                            T3 = np.array(near_pts)
                            _, _, vt3 = np.linalg.svd(T3 - T3.mean(axis=0))
                            ex_, ey_ = float(vt3[0][0]), float(vt3[0][1])
                            remembered = None
                        elif len(inside) >= 3 and basis != 'travel':
                            P3 = np.array([[x, y] for x, y, _ in inside])
                            _, _, vt3 = np.linalg.svd(P3 - P3.mean(axis=0))
                            ex_, ey_ = float(vt3[0][0]), float(vt3[0][1])
                            remembered = None
                        elif remembered is not None:
                            ex_, ey_ = remembered
                        else:
                            ex_, ey_ = ux, uy
                        if (cx_ - sx_) * ex_ + (cy_ - sy_) * ey_ < 0:
                            ex_, ey_ = -ex_, -ey_
                        if remembered is None and (moving or len(inside) >= 3):
                            self._ruled_axes = getattr(self, '_ruled_axes', {})
                            self._ruled_axes[e['label']] = (ex_, ey_)
                        why = (f"The numbers read here ({', '.join(sorted(set(room for _, _, room in inside)))}) fall in "
                               f"the sign's range '{e['label']}', which does NOT include {target}: that corridor is "
                               f"ruled out. Do not go (back) into it or deeper along it.")
                    else:
                        # Nothing read there yet. The sign says the range lies
                        # through its arrow, but a sign can be misread, so one
                        # plate in that corridor is worth confirming -- one,
                        # near the mouth. Only advice here; the exclusion above
                        # takes over the moment a plate in the range is read.
                        if e['arrow'] in ('left', 'right', 'up'):
                            lines.append(
                                f"  The sign says '{e['label']}' lies through the opening its {e['arrow']} arrow points at, "
                                f"and {target} is NOT in that range. Confirm it by reading ONE door plate just inside that "
                                f"opening (the nearest one), then leave: do not explore its frontiers or walk deeper in.")
                        continue
                    bad = []
                    for k, v in keypoints_dict.items():
                        if 'position' not in v or 'robot' in str(v.get('name', '')) or not cand(v):
                            continue
                        px_, py_ = v['position'][:2]
                        al_ = (px_ - sx_) * ex_ + (py_ - sy_) * ey_          # along, from the sign
                        lt_ = abs((px_ - cx_) * (-ey_) + (py_ - cy_) * ex_)  # off the corridor line
                        if al_ > -1.0 and lt_ < 3.5:
                            bad.append(k)
                    lines.append("  " + why)
                    if bad:
                        lines.append("  INSIDE the ruled-out corridor, not valid picks: "
                                     + ", ".join(f"{keypoints_dict[k]['name']} [{k}]" for k in bad))
                    self._ruled_out = {'keys': set(bad), 'label': e['label']}
                    break
                if self._ruled_out is not None:
                    break
        self._corridor = {
            'ux': ux, 'uy': uy, 'rx': rx, 'ry': ry, 'moving': moving, 'est': est,
            'predict': 'ahead' if est is not None else None,
            'ahead': [(a, k) for a, l, k, v in ahead],
            'followed_sign': False,
        }
        return lines

    def joint_state_callback(self, msg: JointState):
        if "pan_joint" in msg.name:
            index = msg.name.index("pan_joint")
            self.pan_joint_state = msg.position[index]

    def publish_tf(self, world_pose, label):
        """Publish arbitrary transform for RViz visualization."""
        transform = TransformStamped()
        transform.header.stamp = self.get_clock().now().to_msg()
        transform.header.frame_id = "map"
        transform.child_frame_id = label
        
        transform.transform.translation.x = world_pose.position.x
        transform.transform.translation.y = world_pose.position.y
        transform.transform.translation.z = world_pose.position.z
        transform.transform.rotation = world_pose.orientation
        
        tf_message = TFMessage(transforms=[transform])
        self.landmark_vis_pub.publish(tf_message)

    def detection_callback(self, msg: Detection2DArray):
        for detection in msg.detections:
            for hypothesis in detection.results:
                hypothesis:ObjectHypothesisWithPose
                obj_class = hypothesis.hypothesis.class_id
                obj_pose = hypothesis.pose.pose
                score = hypothesis.hypothesis.score
                if obj_class in self.landmark_db.landmark_db:
                    landmark_index = self.landmark_db.update_det(obj_class, obj_pose, score)
                else: # never seen this class before
                    landmark_index = 0
                    self.landmark_db.add_det(obj_class, obj_pose, score)

                self.landmark_db.pub_landmark(obj_class, landmark_index, self.landmark_vis_pub)

                if 'sign' in obj_class:
                    self._remember_sign_view(landmark_index, detection, score, msg.header.stamp)
                elif 'room label' in obj_class:
                    self._remember_room_label(landmark_index, detection, obj_pose, msg.header.stamp, score)

    def _remember_room_label(self, landmark_index, detection, obj_pose, stamp=None, score=1.0):
        """Keep the best crop of a room label, to be read later.

        Walking past a door shows its number perfectly well; the old design
        only ever looked when the rig had been driven up to the door and
        stopped. A label seen in passing costs nothing extra to detect, since
        the detector runs every class in one pass anyway.

        Gated on distance and pixel height, not just area: far plates yield
        confident-looking but truncated readings.
        """
        if self.realsense_img is None or self.robot_pose is None:
            return
        b = detection.bbox
        h_px = float(b.size_y)
        self._room_cb_n = getattr(self, '_room_cb_n', 0) + 1
        if self._room_cb_n % 3 == 1:
            self.get_logger().info(
                f'room label det #{self._room_cb_n}: idx {landmark_index} score {score:.2f} bbox {b.size_x:.0f}x{b.size_y:.0f} '
                f'at ({b.center.position.x:.0f},{b.center.position.y:.0f}) plate ({obj_pose.position.x:.1f},{obj_pose.position.y:.1f}) '
                f'robot ({self.robot_pose.position.x:.1f},{self.robot_pose.position.y:.1f})')
        img = self._frame_at(stamp) if stamp is not None else self.realsense_img
        # A plate cut off by the frame edge reads as "T1..." -- not worth an
        # OCR call, and a wrong reading is worse than none. Wait for a full view.
        fh, fw = img.shape[:2]
        cx0, cy0 = float(b.center.position.x), float(b.center.position.y)
        # 2% of the frame, not 4 px: a plate 0.9 m away that ran off the right
        # edge produced a bbox a few pixels inside it, the crop ended mid-word
        # ("T14|"), and the OCR returned T17 at 0.52.
        ex, ey = max(12.0, 0.02 * fw), max(12.0, 0.02 * fh)
        dist = math.hypot(obj_pose.position.x - self.robot_pose.position.x,
                          obj_pose.position.y - self.robot_pose.position.y)
        at_edge = (cx0 - b.size_x / 2 < ex or cy0 - b.size_y / 2 < ey
                   or cx0 + b.size_x / 2 > fw - ex or cy0 + b.size_y / 2 > fh - ey)
        why = None
        if score < ROOM_LABEL_MIN_SCORE:
            # The detector fires on bare wall, door-frame edges and noise at
            # its 0.30 floor; those crops came back "unreadable" at 0.9+ and,
            # being big, kept displacing the real plate's crop until the rig
            # stood 0.7 m from it. Real plates score well above this.
            why = f'score {score:.2f} < {ROOM_LABEL_MIN_SCORE}'
        elif h_px < ROOM_LABEL_MIN_H_PX:
            why = f'height {h_px:.0f} px < {ROOM_LABEL_MIN_H_PX}'
        elif dist > ROOM_LABEL_MAX_DIST:
            why = f'dist {dist:.1f} m > {ROOM_LABEL_MAX_DIST} (plate at {obj_pose.position.x:.1f},{obj_pose.position.y:.1f})'
        elif at_edge:
            why = f'edge (centre {cx0:.0f},{cy0:.0f} size {b.size_x:.0f}x{b.size_y:.0f} in {fw}x{fh})'
        if why is not None:
            # Say why a plate is ignored, once per plate per reason: a run in
            # which nothing gets read must not be silent about it.
            key = (landmark_index, why.split()[0])
            if key not in self._room_skip_logged:
                self._room_skip_logged.add(key)
                self.get_logger().info(f'room label {landmark_index} skipped: {why}')
            return
        area = float(b.size_x) * h_px
        h, w = img.shape[:2]
        cx, cy = float(b.center.position.x), float(b.center.position.y)
        m = 0.4             # margin: the box is often tight or off-centre on the plate
        x0 = max(0, int(cx - b.size_x * (0.5 + m)))
        x1 = min(w, int(cx + b.size_x * (0.5 + m)))
        y0 = max(0, int(cy - b.size_y * (0.5 + m)))
        y1 = min(h, int(cy + b.size_y * (0.5 + m)))
        if x1 - x0 < 8 or y1 - y0 < 8:
            return
        with self.room_lock:
            prev = self.room_labels.get(landmark_index)
            # The label DB is wiped on every door approach, so the same index
            # comes round again for a different plate. T142 sat 0.9 m away for
            # 23 s and was never OCR'd because index 0 still carried T146's
            # 'final' flag. An entry a metre and a half from the new plate is
            # somebody else's.
            if prev is not None and math.hypot(prev['pose'][0] - obj_pose.position.x,
                                               prev['pose'][1] - obj_pose.position.y) > 1.5:
                prev = None
            if prev is not None:
                if prev['area'] >= area:
                    return
                if prev.get('final'):
                    # A final reading is re-checked once the plate fills
                    # twice the pixels it was read from. T111 was read as
                    # 'T110' at 53 px / 2.1 m with 0.91 and locked; the
                    # forty 100-200 px looks that followed were never sent
                    # to the reader and the run never completed.
                    if area < ROOM_RELOOK_RATIO * max(prev.get('read_area', 0.0), 1.0) or prev.get('relooks', 0) >= 2:
                        return
                    prev = dict(prev, relooks=prev.get('relooks', 0) + 1)
                    self.get_logger().info(
                        f"room label {prev.get('read', ('?',))[0]!r} at ({obj_pose.position.x:.1f}, {obj_pose.position.y:.1f}): "
                        f"a look {area / max(prev.get('read_area', 0.0), 1.0):.1f}x bigger -- re-reading")
                    tries = 0
                else:
                    # A clearly better look at a plate already read (but not
                    # finally) earns a fresh set of attempts.
                    tries = 0 if area >= 1.5 * prev.get('read_area', prev['area']) else prev['tries']
            else:
                tries = 0
            self.room_labels[landmark_index] = {
                'crop': img[y0:y1, x0:x1].copy(),
                'area': area, 'h_px': h_px, 'dist': dist,
                'pose': (obj_pose.position.x, obj_pose.position.y),
                'tries': tries,
                'final': False,
                'read': None if prev is None else prev.get('read'),
                'read_area': 0.0 if prev is None else prev.get('read_area', 0.0),
                'history': [] if prev is None else prev.get('history', []),   # low-confidence readings, for the agree rule
                'relooks': 0 if prev is None else prev.get('relooks', 0),
            }

    def _read_room_labels(self):
        """Hand every pending room label to the OCR pool.

        Serial was the wrong shape for this: one plate per 1.5 s tick meant a
        corridor of four doors took six seconds before the last plate was even
        attempted, while the OpenAI round trip is ~1 s and the calls are
        independent. Now everything pending goes out at once, up to
        OCR_WORKERS in flight, and the tick just tops the pool up.
        """
        with self.room_lock:
            free = OCR_WORKERS - len(self._ocr_inflight)
            if free <= 0:
                return
            pending = [(i, v) for i, v in self.room_labels.items()
                       if not v['final'] and v['tries'] < ROOM_LABEL_TRIES
                       and v['area'] > v.get('read_area', 0.0) and i not in self._ocr_inflight]
            pending.sort(key=lambda kv: -kv[1]['area'])
            jobs = []
            for idx, entry in pending[:free]:
                entry['tries'] += 1
                self._ocr_inflight.add(idx)
                prev = entry['read']
                prev_read = None if prev is None else (prev[0], prev[1], entry.get('read_area', 0.0))
                jobs.append((idx, entry['crop'], entry['pose'], entry['area'], entry['h_px'], entry['dist'], prev_read))
        for job in jobs:
            self._ocr_pool.submit(self._ocr_room_worker, *job)

    def _ocr_room_worker(self, idx, crop, pose, area, h_px, dist, prev_read):
        try:
            self._ocr_room(idx, crop, pose, area, h_px, dist, prev_read)
        except Exception as e:
            self.get_logger().warn(f'room label OCR worker failed: {e}')
        finally:
            with self.room_lock:
                self._ocr_inflight.discard(idx)

    def _ocr_room(self, idx, crop, pose, area, h_px, dist, prev_read):
        img = crop
        longest = max(img.shape[:2])
        if longest < ROOM_LABEL_UPSCALE_TO:
            sc = ROOM_LABEL_UPSCALE_TO / longest
            img = cv2.resize(img, (int(img.shape[1] * sc), int(img.shape[0] * sc)),
                             interpolation=cv2.INTER_CUBIC)
        try:
            reading, conf = self.vlm_read_door_cur_image(img)
        except Exception as e:
            self.get_logger().warn(f'room label OCR failed: {e}')
            return
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = 0.0
        # A plate clipped by the frame edge loses its leading digit and reads
        # "T34" (for T134) at 0.89. Fewer digits than the target, or a number
        # outside every sign range covering the target while such a range is
        # being followed, is not believed on one read: it drops to the
        # agree rule (two identical reads).
        tgt = _target_number(self.goal) if self.goal else None
        rd = _parse_label_range(reading) if reading is not None else None
        suspect = None
        if tgt and rd is not None and rd[1] == rd[2]:
            if len(str(rd[1])) < len(str(tgt[1])):
                suspect = 'fewer digits than the target'
            else:
                ranges = [r for v in self.sign_views.values() for e in (v.get('entries') or [])
                          for r in [_parse_label_range(e['label'])] if r and r[1] != r[2] and _range_has(r, tgt)]
                if ranges and self._in_range_read_exists(ranges) and not any(_range_has(r, (rd[0], rd[1])) for r in ranges):
                    suspect = 'outside the sign range being followed'
        if suspect == 'fewer digits than the target':
            # "T13" for T134: a digit is missing, and two clipped looks at the
            # same plate agree with each other just fine -- so no agree rule,
            # no override. Drop it and wait for a full view.
            self.get_logger().info(f'room label {reading!r} conf {conf:.2f}: {suspect} -- dropped')
            with self.room_lock:
                e = self.room_labels.get(idx)
                if e is not None:
                    e['area'] = 0.0
            return
        # Small plates misread with high confidence ("T152" for T132 at 30 px,
        # 0.92): below 35 px a single read is never enough.
        if suspect is None and reading is not None and h_px < 35 and conf >= ROOM_LABEL_MIN_CONF:
            suspect = f'plate only {h_px:.0f} px tall'
        if suspect and conf >= ROOM_LABEL_MIN_CONF:
            self.get_logger().info(f'room label {reading!r} conf {conf:.2f}: {suspect} -- needs a second read')
            conf = ROOM_LABEL_MIN_CONF - 0.01
        try:
            os.makedirs(ROOM_READ_DIR, exist_ok=True)
            tag = 'none' if reading is None else str(reading).replace('/', '_')
            ok = reading is not None and conf >= ROOM_LABEL_MIN_CONF
            cv2.imwrite(os.path.join(
                ROOM_READ_DIR, f"{time.strftime('%H%M%S')}_{'ok' if ok else 'rej'}_{tag}_{conf:.2f}_{dist:.1f}m_{h_px:.0f}px.jpg"), img)
        except Exception:
            pass
        agreed = False
        if reading is not None and conf < ROOM_LABEL_MIN_CONF and conf >= ROOM_LABEL_AGREE_CONF:
            with self.room_lock:
                e = self.room_labels.get(idx)
                if e is not None:
                    hist = e.setdefault('history', [])
                    # Two reads agree only if they are different looks at the
                    # plate (area differs by 30%+): the same blurred crop read
                    # twice gave "T153" for T133 both times.
                    # Accept a low-confidence reading when it repeats from a
                    # clearly different look (30%+ size change) or wins a vote:
                    # three times the same, and never outvoted. Standing 1 m
                    # from T142, six reads went T142, T125, T142, T143, T142,
                    # T142 at 0.5-0.8 and the two-looks rule alone kept
                    # rejecting them for half a minute.
                    same = [a2 for r, a2, *c in hist if isinstance(r, str) and r == reading]
                    same_c = [c[0] if c else 0.0 for r, a2, *c in hist if isinstance(r, str) and r == reading]
                    other = [r for r, a2, *c in hist if isinstance(r, str) and r != reading]
                    # Two reads of the same value at 0.7+ are accepted even from
                    # the same distance: T146 came back 0.74 twice while
                    # walking past and was rejected, so the rig later walked
                    # 9 m back to read that door standing still.
                    agreed = (any(a2 >= 1.3 * area or area >= 1.3 * a2 for a2 in same)
                              or (len(same) + 1 >= 3 and len(same) + 1 > len(other))
                              or (conf >= 0.7 and any(c >= 0.7 for c in same_c)))
                    hist.append((reading, area, conf))
        if reading is None or (conf < ROOM_LABEL_MIN_CONF and not agreed):
            with self.room_lock:
                e = self.room_labels.get(idx)
                if e is not None:
                    # This crop was no good; let the next sighting replace it
                    # whatever its size, instead of "bigger wins" letting a
                    # large junk box hold the slot.
                    e['area'] = 0.0
                    # A big, clear crop the reader calls unreadable with high
                    # confidence is not a number plate at all (a notice, a
                    # panel). Two of those and the door stops earning retries.
                    if reading is None and conf >= 0.85 and h_px >= 40:
                        e['unreadable_hi'] = e.get('unreadable_hi', 0) + 1
            self.get_logger().info(
                f'room label at {dist:.1f} m / {h_px:.0f} px: '
                f'{"unreadable" if reading is None else reading!r} conf {conf:.2f} -- rejected'
                + (f' (will accept if read again as {reading!r})' if reading is not None and conf >= ROOM_LABEL_AGREE_CONF else ''))
            return
        if agreed:
            self.get_logger().info(f'room label {reading!r} read twice at low confidence -- accepting')
        closer = (prev_read is not None and len(prev_read) > 2
                  and area >= ROOM_RELOOK_RATIO * max(prev_read[2], 1.0))
        if prev_read is not None and prev_read[0] != reading:
            pd = re.sub(r'\D', '', str(prev_read[0])); nd = re.sub(r'\D', '', str(reading))
            if len(nd) < len(pd) and pd.endswith(nd):
                return      # "T34" after "T134": the same plate with its first digit cut off
            if conf <= prev_read[1] and not closer and not (len(nd) > len(pd) and nd.endswith(pd)):
                return      # a worse look disagreeing with a better one: ignore

        with self.room_lock:
            if idx in self.room_labels:
                e = self.room_labels[idx]
                e['read'] = (reading, conf)
                e['read_area'] = area
                e['final'] = conf >= ROOM_LABEL_FINAL_CONF
                e['tries'] = 0

        door = self._nearest_door(pose)
        if door is None:
            # No door landmark near the plate yet (the plate is often detected
            # before the door frame is). Do not throw the reading away -- T145
            # was read at 0.93 and then dropped here, and the run never ended.
            # Make the door from the plate's own position.
            dp = Pose(); dp.position.x, dp.position.y = float(pose[0]), float(pose[1]); dp.orientation.w = 1.0
            with self.room_lock:
                if 'a door' in self.landmark_db.landmark_db:
                    door = self.landmark_db.update_det('a door', dp, 0.5)
                else:
                    self.landmark_db.add_det('a door', dp, 0.5); door = 0
            self.get_logger().info(
                f'Read room {reading} at ({pose[0]:.1f}, {pose[1]:.1f}) with no door nearby -- '
                f'created door {door} from the plate')
        note = ''
        if prev_read is not None and prev_read[0] != reading:
            note = f' (overrides {prev_read[0]} @conf {prev_read[1]:.2f})'
        # The door keeps its best reading. The per-plate guard above is lost
        # whenever the plate DB is wiped, and T132 @0.93 was then replaced by
        # T131 @0.64 from a later, worse look.
        # The same number on two plates a couple of metres apart is one
        # misread: T111 came back as 'T110' at 53 px right after the real
        # T110 next to it. The later read is not believed unless it is the
        # clearly closer look of the two; the plate stays open for re-reading.
        for d2, (r2, c2, *h2) in list(self._door_conf.items()):
            if d2 == door or r2 != reading:
                continue
            p2 = self._door_xy(d2)
            if p2 is None or math.hypot(p2[0] - pose[0], p2[1] - pose[1]) > 5.0:
                continue
            if h_px >= 1.5 * (h2[0] if h2 else 0.0) and conf >= ROOM_LABEL_MIN_CONF:
                break
            self.get_logger().info(
                f'room label {reading!r} conf {conf:.2f} ({h_px:.0f} px): door {d2} already carries it '
                f'{math.hypot(p2[0] - pose[0], p2[1] - pose[1]):.1f} m away -- not believed, will re-read closer')
            with self.room_lock:
                e = self.room_labels.get(idx)
                if e is not None:
                    e['final'] = False
                    e['area'] = 0.0
                    e['read_area'] = area
            return
        old = self._door_conf.get(door)
        if old is not None and old[0] != reading:
            old_h0 = old[2] if len(old) > 2 else 0.0
            if h_px >= 1.5 * old_h0 and conf >= ROOM_LABEL_MIN_CONF and conf >= old[1] - 0.1:
                # A look half again as tall as the one the door was labelled
                # from, read confidently: the closer look wins outright.
                self.get_logger().info(
                    f'room label {reading!r} conf {conf:.2f} at {h_px:.0f} px overrides door {door} = {old[0]!r} '
                    f'@conf {old[1]:.2f} read at {old_h0:.0f} px (closer look)')
            elif conf <= old[1]:
                self.get_logger().info(
                    f'room label {reading!r} conf {conf:.2f} would replace door {door} = {old[0]!r} @conf {old[1]:.2f} -- kept the old one')
                return
            # One digit different from what this door already carries ("T153"
            # for T133): the classic 3/5, 1/7, 0/8 confusion. A single better
            # score is not enough to overturn it -- either the same new value
            # is read again on this door, or it comes from a clearly closer
            # look with a clearly higher score.
            od, nd = re.sub(r'\D', '', str(old[0])), re.sub(r'\D', '', str(reading))
            if (len(od) == len(nd) and sum(a != b for a, b in zip(od, nd)) == 1
                    and not (h_px >= 1.5 * old_h0 and conf >= ROOM_LABEL_MIN_CONF and conf >= old[1] - 0.1)):
                votes = self._door_votes.setdefault(door, {})
                votes[reading] = votes.get(reading, 0) + 1
                old_h = old[2] if len(old) > 2 else 0.0
                if votes[reading] < 2 and not (conf >= old[1] + 0.2 and h_px >= 1.2 * old_h):
                    self.get_logger().info(
                        f'room label {reading!r} conf {conf:.2f} differs from door {door} = {old[0]!r} @conf {old[1]:.2f} in one digit '
                        f'-- not overriding on one read')
                    return
        self._door_conf[door] = (reading, conf, h_px)
        self.landmark_db.mark_visited('a door', door, label=reading)
        self.get_logger().info(
            f'Read room {reading} in passing (conf {conf:.2f}, {dist:.1f} m, '
            f'{h_px:.0f} px) -> door {door}{note}')
        if self.landmark_handlers._is_goal(reading):
            self.announce_found(reading, pose)

    def _sign_signature(self):
        return tuple(sorted((i, e['label'], e['arrow']) for i, v in self.sign_views.items()
                            for e in (v.get('entries') or [])))

    def _next_planned(self, keypoints_dict):
        """Pop the next still-valid planned landmark, re-resolved in the fresh
        keypoints. Returns the keypoints entry or None (ask the VLM)."""
        sig = self._sign_signature()
        if self._plan_sign_sig is not None and sig != self._plan_sign_sig and self.plan_queue:
            self.get_logger().info("PLAN dropped: a sign was read since it was made")
            self.plan_queue = []
        self._plan_sign_sig = sig
        while self.plan_queue:
            want = self.plan_queue.pop(0)
            name = want.get('name', '')
            cand = None
            if name.startswith('Frontier'):
                wx, wy = want.get('position', (None, None))[:2] if 'position' in want else (None, None)
                if wx is None:
                    continue
                best = None
                for k, v in keypoints_dict.items():
                    if v.get('name', '').startswith('Frontier') and 'position' in v:
                        d = math.hypot(v['position'][0] - wx, v['position'][1] - wy)
                        if d <= PLAN_FRONTIER_MATCH_M and (best is None or d < best[0]):
                            best = (d, v)
                cand = best[1] if best else None
            else:
                for v in keypoints_dict.values():
                    if v.get('name') == name:
                        cand = v
                        break
            if cand is None or str(cand.get('name', '')).startswith('Visited_'):
                self.get_logger().info(f"PLAN: {name} is gone or already visited -- skipping")
                continue
            # Refresh: a plate read since the plan was made (T132 while
            # walking to the previous step) can rule the corridor out, and
            # the planned frontier deeper in must not be walked to anyway.
            try:
                self._corridor_context(keypoints_dict, f"Room {self.goal}" if self.goal else "")
            except Exception as e:
                self.get_logger().warn(f'corridor refresh failed: {e}')
            ro = getattr(self, '_ruled_out', None)
            if ro and any(v is cand for k, v in keypoints_dict.items() if k in ro['keys']):
                self.get_logger().info(f"PLAN: {name} is inside the ruled-out corridor -- skipping")
                continue
            if 'position' in cand and recently_abandoned(*cand['position'][:2]):
                continue
            cor = self._corridor
            # Behind is measured along the corridor's own axis, not the way
            # the carrier happens to be walking: when they turn round for a
            # door, the travel axis flips and a lobby frontier 12 m back
            # counted as "ahead" and was walked to from the plan queue.
            ax = (cor['ux'], cor['uy']) if cor and 'ux' in cor else self._travel_axis()
            if (cor and (cor.get('followed_sign') or cor.get('predict') == 'ahead')
                    and cor.get('predict') != 'behind' and 'position' in cand and ax is not None
                    and self.robot_pose is not None):
                rx_, ry_, _ = pose_msg_to_xyyaw(self.robot_pose)
                along = (cand['position'][0] - rx_) * ax[0] + (cand['position'][1] - ry_) * ax[1]
                if along < -CORRIDOR_BACK_M:
                    self.get_logger().info(f"PLAN: {name} is {-along:.0f} m behind in this corridor -- skipping")
                    continue
            self.get_logger().info(f"PLAN: next {cand['name']} ({len(self.plan_queue)} more queued)")
            msg = String(); msg.data = f"PLAN: continuing to {cand['name']} without asking the VLM. Chosen landmark: [{[k for k, v in keypoints_dict.items() if v is cand][0]}]"
            self.vlm_text_pub.publish(msg)
            jm = String(); jm.data = str(keypoints_dict); self.landmark_json_pub.publish(jm)
            return cand
        return None

    def announce_found(self, reading, xy):
        """Say, loudly and on the wire, that the target has been found.

        Until now "Room T145 found!" went to the node's own log and nowhere
        else: the carrier's watcher kept printing range and bearing to the last
        door goal and the green arrow stayed in RViz, so a successful run looked
        exactly like a stuck one. Publish it where the operator is looking, drop
        the approach arrow, and mark the spot.
        """
        if self.goal_reached:
            return
        self.goal_reached = True
        x, y = float(xy[0]), float(xy[1])
        self.get_logger().info(f'Room {self.goal} found! ({reading} at {x:.1f}, {y:.1f})')
        msg = String()
        msg.data = (f"MISSION COMPLETE: Room {reading} found at map ({x:.1f}, {y:.1f}). "
                    f"You are there -- stop here.")
        self.vlm_text_pub.publish(msg)
        gone = Marker(); gone.header.frame_id = 'map'; gone.ns = 'Approach'; gone.id = 0
        gone.action = Marker.DELETE
        self.goal_marker_pub.publish(gone)
        done = Marker(); done.header.frame_id = 'map'; done.ns = 'Done'; done.id = 0
        done.type = Marker.SPHERE; done.action = Marker.ADD
        done.pose.position.x = x; done.pose.position.y = y; done.pose.position.z = 0.5
        done.pose.orientation.w = 1.0
        done.scale.x = done.scale.y = done.scale.z = 0.6
        done.color.r, done.color.g, done.color.b, done.color.a = 0.1, 1.0, 0.1, 0.9
        self.goal_marker_pub.publish(done)

    def _door_xy(self, idx):
        """Map position of door landmark `idx`, or None."""
        db = self.landmark_db.landmark_db.get('a door')
        if not db or idx >= len(db['positions']):
            return None
        return float(db['positions'][idx][0]), float(db['positions'][idx][1])

    def _nearest_door(self, xy):
        """Index of the closest door landmark, or None if none is close."""
        db = self.landmark_db.landmark_db.get('a door')
        if not db or not db['positions']:
            return None
        pos = np.array([p[:2] for p in db['positions']])
        d = np.linalg.norm(pos - np.array(xy), axis=1)
        i = int(np.argmin(d))
        return i if d[i] <= ROOM_LABEL_DOOR_RADIUS else None

    # ------------------------------------------------------------ sign geometry
    def _sign_sides(self, sx, sy, reader, keypoints_dict, skip_key):
        """Landmarks ahead of `reader`, split into LEFT/RIGHT of the sign.

        Returns {'LEFT': [...], 'RIGHT': [...]} of (|lateral|, forward, key,
        name, lateral, text), nearest-to-the-sign first, or None if the reader
        stood on top of the sign. Geometry comes from where the photo was
        taken, never from the detected face normal -- four depth samples on a
        30 cm plate gave bearings that jumped 134 -> 9 deg for one sign.
        """
        ux, uy = sx - reader[0], sy - reader[1]
        nrm = math.hypot(ux, uy)
        if nrm <= 0.3:
            return None
        ux, uy = ux / nrm, uy / nrm              # reader -> sign (view axis)
        lx_, ly_ = -uy, ux                        # reader's LEFT (+90 deg)
        sides = {'LEFT': [], 'RIGHT': [], 'LEFT_read': [], 'RIGHT_read': []}
        rx2 = ry2 = None
        if self.robot_pose is not None:
            rx2, ry2, _ = pose_msg_to_xyyaw(self.robot_pose)
        for k2, v2 in keypoints_dict.items():
            if k2 == skip_key or 'position' not in v2 or 'robot' in v2.get('name', ''):
                continue
            px_, py_ = v2['position'][:2]
            fwd = (px_ - reader[0]) * ux + (py_ - reader[1]) * uy
            lat = (px_ - sx) * lx_ + (py_ - sy) * ly_        # left of the SIGN
            if fwd < 0.5:
                continue                          # behind the reader: an arrow never means that
            side = 'LEFT' if lat >= 0.0 else 'RIGHT'
            name = str(v2.get('name', ''))
            # A visited door is a number on the wall, not a place to go. Listing
            # it as a candidate made the VLM pick "the first useful thing on the
            # left list" -- a door it had read ten minutes earlier -- and walk
            # the carrier 20 m back. Keep the number as context, drop the entry.
            if name.startswith('Visited_'):
                if v2.get('room'):
                    sides[side + '_read'].append((fwd, f"{v2['room']} [{k2}]"))
                continue
            # Where the rig is NOW matters too. Once the corridor door beside
            # the sign had been visited, the next LEFT entry was a door back by
            # the sign, and the VLM dutifully walked the rig back to it. An
            # opening already behind the rig is not offered at all.
            if rx2 is not None and (px_ - rx2) * ux + (py_ - ry2) * uy < -1.0:
                continue
            beside = ('right beside the sign' if abs(lat) < 1.0
                      else f"{abs(lat):.0f} m to the {'left' if lat > 0 else 'right'} of the sign")
            sides[side].append((abs(lat), fwd, k2, name, lat,
                                f"{name} [{k2}] ({beside}, {fwd:.0f} m ahead)"))
        for side in ('LEFT', 'RIGHT'):
            sides[side].sort(key=lambda t: (t[0], -t[1]))
            sides[side + '_read'].sort()
        return sides

    def _read_signs(self):
        """OCR one directional sign: its label ranges and their arrows."""
        with self.room_lock:
            pend = [(i, v) for i, v in self.sign_views.items()
                    if v.get('tries', 0) < SIGN_READ_TRIES
                    and v.get('crop', v['img']).shape[0] >= SIGN_MIN_H_PX
                    and ((not v.get('final') and v['area'] > 1.5 * v.get('read_area', 0.0))
                         or v['area'] >= SIGN_RELOOK_RATIO * max(v.get('read_area', 0.0), 1.0))]
            if not pend:
                return
            idx, view = max(pend, key=lambda kv: kv[1]['area'])
            view['tries'] = view.get('tries', 0) + 1
            img, area = view.get('crop', view['img']), view['area']
            img_h = img.shape[0]
        longest = max(img.shape[:2])
        if longest < 640:
            sc = 640.0 / longest
            img = cv2.resize(img, (int(img.shape[1] * sc), int(img.shape[0] * sc)),
                             interpolation=cv2.INTER_CUBIC)
        # Close-up AND the whole frame: the crop carries the digits, the frame
        # carries the context (which arrow belongs to which label) and rescues
        # a crop that turned out too tight.
        full = view['img']
        fh, fw = full.shape[:2]
        if max(fh, fw) > 960:
            sc = 960.0 / max(fh, fw)
            full = cv2.resize(full, (int(fw * sc), int(fh * sc)), interpolation=cv2.INTER_AREA)
        try:
            raw = self.ocr_client.images_text_query_vlm([img, full], VLMPrompts.sign_entries_prompt())
            try:
                sd = os.path.expanduser('~/tips_ws/logs/sign_reads'); os.makedirs(sd, exist_ok=True)
                tag = re.sub(r'[^A-Za-z0-9_-]', '', str(raw)[:24]) or 'none'
                cv2.imwrite(os.path.join(sd, f"{time.strftime('%H%M%S')}_sign{idx}_{img_h}px_{tag}.jpg"), img)
            except Exception:
                pass
        except Exception as e:
            self.get_logger().warn(f'sign OCR failed: {e}')
            return
        entries = _parse_sign_entries(raw)
        # Room plates get detected as directional signs. A big crop that reads
        # as a single number with no arrow, or as nothing twice, is one of
        # those: stop treating it as a sign (and stop walking up to it).
        def _has_range_arrow(es):
            for e in es:
                r_ = _parse_label_range(e['label'])
                if r_ and r_[1] != r_[2] and e['arrow'] in ('left', 'right', 'up', 'down'):
                    return True
            return False
        if img_h >= SIGN_FINAL_H_PX and not _has_range_arrow(entries):
            with self.room_lock:
                v0 = self.sign_views.get(idx)
                if v0 is not None:
                    v0['plain'] = v0.get('plain', 0) + 1
                    plain = v0['plain']
                else:
                    plain = 0
            if plain >= 2 or (entries and not _has_range_arrow(entries)):
                self.get_logger().info(f"sign {idx}: reads {raw!r} from a {img_h} px crop -- not a directional sign, dropping it")
                try:
                    self.landmark_db.mark_useless('a directional sign', idx)
                except Exception:
                    pass
                with self.room_lock:
                    if idx in self.sign_views:
                        self.sign_views[idx]['not_sign'] = True
                        self.sign_views[idx]['final'] = True
                return
        tgt_ = _target_number(self.goal) if self.goal else None
        if entries and tgt_:
            kept_e = []
            for e in entries:
                r_ = _parse_label_range(e['label'])
                if r_ and (len(str(r_[1])) != len(str(tgt_[1])) or len(str(r_[2])) != len(str(tgt_[1]))):
                    self.get_logger().info(f"sign {idx}: '{e['label']}' has the wrong digit count for this building -- misread, ignored")
                    continue
                kept_e.append(e)
            entries = kept_e
        if not entries:
            # Nothing usable: leave read_area alone so the next pass retries
            # (up to SIGN_READ_TRIES), and show what came back.
            self.get_logger().info(
                f'sign {idx}: no entries from OCR (try {view["tries"]}/{SIGN_READ_TRIES}): '
                f'{str(raw)[:120]!r}')
            return
        with self.room_lock:
            if idx in self.sign_views:
                v = self.sign_views[idx]
                old_e = v.get('entries') or []
                if old_e and area >= SIGN_RELOOK_RATIO * max(v.get('read_area', 0.0), 1.0):
                    self.get_logger().info(
                        f"sign {idx}: closer look ({area:.0f} px^2 vs {v.get('read_area', 0.0):.0f}) replaces "
                        + ", ".join(e['label'] + ' ' + e['arrow'] for e in old_e))
                    old_e = []
                # Otherwise union, never replace. Two reads of one plate disagreed
                # on the last digits (T131-T150 vs T131-T136); keeping only the
                # newer one dropped the range the target was in.
                seen = {(e['label'], e['arrow']) for e in old_e}
                merged = old_e + [e for e in entries if (e['label'], e['arrow']) not in seen]
                v['entries'] = merged
                v['read_area'] = area
                v['tries'] = 0
                # A range with a real arrow is all the rule ever uses: stop
                # spending OCR calls (and inviting noise) on this sign.
                def _is_range_arrow(e):
                    r = _parse_label_range(e['label'])
                    return r is not None and r[1] != r[2] and e['arrow'] in ('left', 'right', 'up')
                # Final only from a close look; a small crop's reading stays
                # open to be replaced when the rig gets nearer.
                v['final'] = any(_is_range_arrow(e) for e in merged) and img_h >= SIGN_FINAL_H_PX
                kept = merged
        # A sign that has been read is context, not a destination: it kept
        # turning up as "Unvisited_directional sign" in the candidate lists
        # and the VLM walked the carrier back to it.
        try:
            self.landmark_db.mark_visited('a directional sign', idx)
        except Exception as e:
            self.get_logger().warn(f'could not mark sign {idx} visited: {e}')
        self.get_logger().info(
            f"sign {idx} reads: " + ", ".join(f"{e['label']} {e['arrow']}" for e in entries)
            + (f"  (all readings: {', '.join(e['label'] + ' ' + e['arrow'] for e in kept)})" if len(kept) > len(entries) else ""))

    def _remember_sign_view(self, landmark_index, detection, score, stamp=None):
        """Keep the clearest camera frame in which this sign was seen.

        An arrow on a sign only means anything together with what is around it
        -- in this building a left arrow next to an opening that recedes
        *forward* means "through that opening", not "turn 90 degrees left". No
        amount of post-processing recovers that from a cardinal label, so the
        frame itself is kept and handed to the VLM later.

        Snapshotting here rather than in handle_sign_landmark matters: the
        handler runs seconds to a minute after the sighting (and on a handheld
        rig never drives anywhere), by which point the camera is pointing
        somewhere else entirely.
        """
        if self.realsense_img is None:
            return
        # Bigger box == closer or better framed, which beats raw score as a
        # proxy for "readable".
        area = float(detection.bbox.size_x) * float(detection.bbox.size_y)
        prev = self.sign_views.get(landmark_index)
        if prev is not None and prev['area'] >= area:
            # A fresh, comparable frame is worth another go when the earlier
            # crops came back empty -- three "[]" from one blurred frame used
            # to end reading for good.
            fresh = (not prev.get('entries') and prev.get('tries', 0) >= SIGN_READ_TRIES
                     and area >= 0.8 * prev['area'])
            if not fresh:
                return
        robot_xy = None
        if self.robot_pose is not None:
            rx, ry, _ = pose_msg_to_xyyaw(self.robot_pose)
            robot_xy = (round(rx, 2), round(ry, 2))
        # A tight crop for reading the sign; the full frame stays for the VLM,
        # which needs the surroundings to make sense of an arrow.
        img = self._frame_at(stamp) if stamp is not None else self.realsense_img
        h, w = img.shape[:2]
        b = detection.bbox
        cx, cy = float(b.center.position.x), float(b.center.position.y)
        ex, ey = max(12.0, 0.02 * w), max(12.0, 0.02 * h)
        if (cx - b.size_x / 2 < ex or cy - b.size_y / 2 < ey
                or cx + b.size_x / 2 > w - ex or cy + b.size_y / 2 > h - ey):
            return                      # partly out of frame: arrow or range may be cut
        x0 = max(0, int(cx - b.size_x * 0.65)); x1 = min(w, int(cx + b.size_x * 0.65))
        y0 = max(0, int(cy - b.size_y * 0.65)); y1 = min(h, int(cy + b.size_y * 0.65))
        crop = img[y0:y1, x0:x1].copy() if (x1 - x0 > 8 and y1 - y0 > 8) else img.copy()
        self.sign_views[landmark_index] = {
            'img': img.copy(),
            'crop': crop,
            'score': float(score),
            'area': area,
            'robot_xy': robot_xy,
            # What the OCR model read off it, kept across better snapshots.
            'entries': None if prev is None else prev.get('entries'),
            # A clearly better look earns fresh attempts. Without this, three
            # empty reads of a small, dark first sighting used up the budget and
            # the sign was never read again however close the rig later came.
            'tries': 0 if (prev is None or area >= 1.5 * prev['area']
                           or (not prev.get('entries') and prev.get('tries', 0) >= SIGN_READ_TRIES)) else prev.get('tries', 0),
            'read_area': 0.0 if prev is None else prev.get('read_area', 0.0),
            # Carry the lock too. Losing it here let a bigger snapshot trigger
            # a re-read that came back "T131-T136" and displaced "T131-T150".
            'final': False if prev is None else prev.get('final', False),
        }
    
    def _frame_at(self, stamp):
        """Camera frame nearest `stamp` (within 0.5 s), else the latest one."""
        with self.frames_lock:
            snap = list(self.frames)
        if not snap:
            return self.realsense_img
        want = stamp.sec + stamp.nanosec * 1e-9
        st, img = min(snap, key=lambda e: abs(e[0] - want))
        return img if abs(st - want) < 0.5 else self.realsense_img

    def realsense_callback(self, msg: Image):
        # Convert to OpenCV image and call the image query function of vlm client asking what's in the image, publish the result to a ros topic
        self.realsense_img = self.cv_bridge.imgmsg_to_cv2(msg, 'rgb8')
        # Keep ~3 s of stamped frames. Detections arrive ~100+ ms after their
        # image, so cropping the LATEST frame with an old bbox puts the crop on
        # whatever the camera has swung to since -- one saved "room label" crop
        # was bare wall, read as unreadable at 99% confidence. Crops are taken
        # from the frame the detector actually saw.
        with self.frames_lock:
            self.frames.append((msg.header.stamp.sec + msg.header.stamp.nanosec * 1e-9,
                                self.realsense_img))

    def _publish_frontier_markers(self, fd):
        """RViz arrows for the current frontier set, without DELETEALL.

        A DELETEALL marker at the head of a MarkerArray took the ADD markers
        behind it down with it in RViz2 -- /frontiers was streaming at 1 Hz
        with [DELETEALL, ADD ...] and nothing was drawn, while /goal_marker
        (a lone ADD) showed fine. Stable ids instead: frontier i is always
        (ns='frontiers', id=i), and ids no longer in use get an explicit DELETE.
        """
        arr = MarkerArray()
        names = list(fd.items())
        for i, (fname, f) in enumerate(names):
            fx, fy = f['position_xy']
            m = xyyaw_to_marker(rclpy.time.Time(), 'frontiers', fx, fy, f.get('yaw', 0.0))
            m.id = i
            arr.markers.append(m)
        prev = getattr(self, '_frontier_marker_count', 0)
        for i in range(len(names), prev):
            m = Marker(); m.header.frame_id = 'map'; m.ns = 'frontiers'; m.id = i
            m.action = Marker.DELETE
            arr.markers.append(m)
        self._frontier_marker_count = len(names)
        self.marker_pub.publish(arr)

    def _frontier_report(self, res):
        """Log the frontier pipeline's stage counts every ~10 s, and dump a
        picture when a big free area yields almost nothing -- "why is there no
        frontier up there" should be answerable from the log, not a replay."""
        import mm_dev.frontier_detection.frontier_detector as FD
        d = FD.LAST_DEBUG
        if not d:
            return
        now = time.monotonic()
        if now - getattr(self, '_fr_report_t', 0.0) < 10.0:
            return
        self._fr_report_t = now
        n_final = d.get('final', 0)
        self.get_logger().info(
            f"[frontiers] navigable comps {d.get('components')} | robot comp {d.get('robot_cells')}/{d.get('navigable_cells')} cells"
            f" | erode {d.get('erode_cells')} -> comps {d.get('eroded_components')}, reach {d.get('reach_cells')} cells"
            f" | segments {d.get('segments')} -> gap ok {d.get('gap_ok')} -> reach ok {d.get('reach_ok')} -> final {n_final}"
            f" (after cost filter: {len(res[1]) if res and res[1] is not None else 0})")
        if n_final <= 1 and (d.get('robot_cells') or 0) > 3000 and now - getattr(self, '_fr_dump_t', 0.0) > 30.0:
            self._fr_dump_t = now
            try:
                out_dir = os.path.expanduser('~/tips_ws/logs/frontier_debug'); os.makedirs(out_dir, exist_ok=True)
                mine, reach = d.get('mine'), d.get('reach')
                h, w = mine.shape
                im = np.zeros((h, w, 3), np.uint8)
                im[mine > 0] = (0, 120, 0)
                if reach is not None:
                    im[reach > 0] = (0, 200, 0)
                for seg, keep in zip(d.get('seg_list', []), d.get('seg_keep', [])):
                    for p in seg[::2]:
                        x, y = int(p[0][0]), int(p[0][1])
                        if 0 <= x < w and 0 <= y < h:
                            im[y, x] = (255, 0, 255) if keep else (0, 255, 255)
                rp = d.get('robot_px')
                if rp is not None:
                    cv2.circle(im, (int(rp[0]), int(rp[1])), 6, (255, 200, 0), 2)
                ys, xs = np.nonzero(mine)
                if xs.size:
                    x0, x1 = max(0, xs.min() - 40), min(w, xs.max() + 40); y0, y1 = max(0, ys.min() - 40), min(h, ys.max() + 40)
                    im = im[y0:y1, x0:x1]
                im = cv2.resize(im, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST)
                cv2.putText(im, "dark green=robot comp  green=reach(>=1.5m passages)  magenta=kept seg  yellow=dropped  orange=robot",
                            (6, 18), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1)
                fn = os.path.join(out_dir, time.strftime('%H%M%S') + f'_final{n_final}.png')
                cv2.imwrite(fn, im)
                self.get_logger().info(f'[frontiers] few frontiers on a large map -- debug image {fn}')
            except Exception as e:
                self.get_logger().warn(f'[frontiers] debug dump failed: {e}')

    def refresh_frontiers(self):
        """Recompute frontiers from the current costmap and republish them.

        Owns last_frontier_dict between VLM decisions so the map render, the
        RViz arrows and the chooser's candidates all track the live costmap
        instead of the one from the last decision.
        """
        if self.costmap is None or self.robot_pose is None:
            return
        try:
            res = get_frontiers_with_filtering(
                self.costmap, self.robot_pose, self.tf_buffer, FOOTPRINT_POLYGON,
                config, self, self.marker_pub)
        except Exception as e:
            self.get_logger().warn(f'frontier refresh failed: {e}',
                                   throttle_duration_sec=10.0)
            return
        self._frontier_cache = (time.monotonic(), res)
        self._frontier_report(res)
        fd = {}
        if res[1] is not None:
            for pose in res[1]:
                if recently_abandoned(pose.position.x, pose.position.y) and \
                        not self._ahead_in_corridor(pose.position.x, pose.position.y):
                    continue
                _, _, fyaw = pose_msg_to_xyyaw(pose)
                fd[f"Frontier_{len(fd)}"] = {
                    'position_xy': [pose.position.x, pose.position.y], 'yaw': fyaw}
        self.last_frontier_dict = fd
        self._publish_frontier_markers(fd)

    def publish_landmark_map(self):
        """Re-render /frontier_image from whatever state is current.

        Runs on a timer so the map keeps refreshing while the main loop is
        blocked inside a landmark handler, and starts as soon as a costmap and
        a pose exist rather than waiting for the loop's first full pass.
        """
        if self.costmap is None or self.robot_pose is None:
            return
        try:
            t0 = time.perf_counter()
            costmap_image, _ = vis_landmarks(
                self.costmap,
                self.last_frontier_dict,
                self.landmark_db.get_landmarks_dict(),
                self.robot_pose)
            t_render = time.perf_counter() - t0
            t1 = time.perf_counter()
            self.pub_frontier_img(costmap_image)
            t_pub = time.perf_counter() - t1
            # Report from the publishing side: a Python subscriber cannot count
            # a multi-MB image topic reliably, so measuring the rate downstream
            # understates it. Numbers here are what actually went out.
            self._map_stats.append((t_render, t_pub))
            if len(self._map_stats) >= 25:
                now = time.perf_counter()
                span = now - self._map_stats_t0
                r = sum(s[0] for s in self._map_stats) / len(self._map_stats)
                p = sum(s[1] for s in self._map_stats) / len(self._map_stats)
                self.get_logger().info(
                    f'[map] {len(self._map_stats)/span:.2f} Hz published '
                    f'(render {r*1000:.0f} ms, publish {p*1000:.0f} ms, '
                    f'target {1.0/LANDMARK_MAP_PERIOD:.1f} Hz)')
                self._map_stats.clear()
                self._map_stats_t0 = now
        except Exception as e:
            self.get_logger().warn(f'landmark map render skipped: {e}')

    def pub_frontier_img(self, costmap_image):
        # vis_landmarks already sizes its output (MAP_OUTPUT_PX) and stamps the
        # labels afterwards, so nothing here should need resizing. Scaling a
        # second time is what used to blur the numbers as the map grew: they
        # were drawn at map scale and then shrunk. Kept only as a ceiling for a
        # pathological frame.
        h, w = costmap_image.shape[:2]
        longest = max(h, w)
        if longest > LANDMARK_MAP_MAX_PX:
            s = LANDMARK_MAP_MAX_PX / longest
            costmap_image = cv2.resize(
                costmap_image, (int(w * s), int(h * s)),
                interpolation=cv2.INTER_AREA)
        costmap_image_msg = self.cv_bridge.cv2_to_imgmsg(costmap_image, encoding="bgr8")
        costmap_image_msg.header.frame_id = 'map'
        costmap_image_msg.header.stamp = self.get_clock().now().to_msg()
        self.frontier_image_pub.publish(costmap_image_msg)

    def vlm_web_search(self):
        prompt = VLMPrompts.web_search_decision_prompt(self.goal)
        vlm_result = self.vlm_client.text_query_vlm(prompt)
        self.get_logger().info(f"Web search VLM result: {vlm_result}")
        vlm_result = vlm_result.split(';')
        do_search, keywords = vlm_result[0].lower(), vlm_result[1]
        if "yes" in do_search:
            # search
            search_result = self.vlm_client.search(keywords)
            # update goal
            self.goal = search_result
        return do_search
    
    def vlm_describe_cur_image(self):
        prompt = VLMPrompts.describe_scene_prompt()
        vlm_result = self.vlm_client.image_text_query_vlm(self.realsense_img, prompt)
        return vlm_result

    def vlm_read_door_cur_image(self, image=None):
        """Use VLM to read the door number in the current image.

        Returns (reading, confidence), where reading is None when nothing was
        legible. The reading stays a STRING: rooms in this building are
        labelled T106, T109, and int() threw those away as unreadable -- the
        one building the rig actually walks was the one whose numbering the
        parser could not represent.
        """
        prompt = VLMPrompts.read_door_number_prompt()
        vlm_result = self.ocr_client.image_text_query_vlm(
            self.realsense_img if image is None else image, prompt)
        self.get_logger().info(f"Door number VLM result: {vlm_result}")
        try:
            head, _, tail = str(vlm_result).partition(';')
            reading = head.strip().strip('.').upper().replace(' ', '')
            confidence = float(tail.strip()) if tail.strip() else -1.0
        except ValueError:
            return None, -1.0
        # -1 = no sign visible, -2 = sign visible but unreadable (see the
        # prompt). Both mean "no reading", not "room minus one".
        if not reading or reading.startswith('-'):
            return None, confidence
        return reading, confidence

    def vlm_read_sign_curr_image(self):
        """Use VLM to read directional sign from current image."""
        prompt = VLMPrompts.read_sign_directions_prompt()
        vlm_result = self.ocr_client.image_text_query_vlm(self.realsense_img, prompt)
        self.get_logger().info(f"Sign directions VLM result: {vlm_result}")
        try:
            sign_dict = ast.literal_eval(vlm_result)
            return sign_dict
        except ValueError:
            return {}

    def vlm_update_sign_directions(self, sign_dict, costmap_image):
        prompt = VLMPrompts.convert_sign_directions_prompt(sign_dict)

        vlm_result = self.vlm_client.images_text_query_vlm([costmap_image], prompt)
        self.get_logger().info(f"Sign directions conversion VLM result: {vlm_result}")
        try:
            sign_dict = ast.literal_eval(vlm_result)
            return sign_dict
        except ValueError:
            return {}

    def _sign_context(self, keypoints_dict):
        """Photos of nearby signs plus the geometry needed to place them.

        Returns (images, lines). A photo on its own is unanchored -- the VLM
        cannot tell which way "left" points without knowing where the sign sits
        and which way it faces -- so each photo is paired with the sign's map
        position, the bearing of its face, and where the robot stood to take it.

        Only the SIGN_VIEW_LIMIT nearest signs are attached; a long run
        accumulates a couple of dozen and every extra photo is real money.
        """
        if self.robot_pose is None:
            return [], []
        rx, ry, _ = pose_msg_to_xyyaw(self.robot_pose)

        db = self.landmark_db.landmark_db.get('a directional sign')
        if not db:
            return [], []

        # Map landmark index -> the number the map is labelled with, so the
        # prompt can name a sign the same way the icons do.
        # Match on the landmark index, not on a rebuilt name string. The names
        # carry a Visited_/Unvisited_ prefix that flips the moment a sign is
        # inspected, and reconstructing them here meant the lookup missed from
        # then on -- the photo silently stopped being attached exactly when the
        # sign became worth reasoning about, and the VLM fell back to "the only
        # sign has already been visited with no directions provided".
        keypt_of_idx = {}
        for k, v in keypoints_dict.items():
            nm = v.get('name', '')
            if 'directional sign' not in nm:
                continue
            try:
                keypt_of_idx[int(nm.rsplit('_', 1)[-1])] = k
            except ValueError:
                continue

        cands = []
        for idx, view in self.sign_views.items():
            if idx >= len(db['positions']):
                continue
            sx, sy = db['positions'][idx][:2]
            dist = math.hypot(sx - rx, sy - ry)
            cands.append((dist, idx, sx, sy, view))
        cands.sort(key=lambda c: c[0])

        images, lines = [], []
        for dist, idx, sx, sy, view in cands[:SIGN_VIEW_LIMIT]:
            kp = keypt_of_idx.get(idx)
            if kp is None:
                continue
            face = None
            try:
                q = db['orientations'][idx]
                face = math.degrees(quaternion_to_yaw(q)) % 360.0
            except Exception:
                pass
            img = view['img']
            h, w = img.shape[:2]
            if max(h, w) > SIGN_VIEW_MAX_PX:
                sc = SIGN_VIEW_MAX_PX / max(h, w)
                img = cv2.resize(img, (int(w * sc), int(h * sc)),
                                 interpolation=cv2.INTER_AREA)
            images.append(img)
            seen_txt = (f", photographed from map {view['robot_xy']}"
                        if view['robot_xy'] else "")
            line = (f"  Photo {len(images)}: map icon [{kp}], a directional sign at "
                    f"map ({sx:.1f}, {sy:.1f}){seen_txt}, {dist:.1f} m from you now.")
            ents = view.get('entries') or []
            if ents:
                line += ("\n      It reads: " + "; ".join(
                    f"'{e['label']}' with a {e['arrow']} arrow" if e['arrow'] != 'none' else f"'{e['label']}'"
                    for e in ents) + ".")
            # Reader geometry from the PHOTO, not from the detected face normal.
            # The normal comes from four depth samples on a 30 cm plate and its
            # bearing jumped between 134 and 9 degrees for one and the same sign
            # -- so "left of it" pointed anywhere. Where the photo was taken is
            # known exactly, and a sign is readable only from the side it faces.
            reader = view.get('robot_xy') or (rx, ry)
            # Once a room number inside this sign's range has been read, the
            # rig is in the corridor the arrow meant. From then on the sign's
            # LEFT/RIGHT geometry (anchored to the photographer) only misleads
            # -- it kept naming "the first opening" thirty metres back -- so
            # say the sign is done and hand over to the corridor block.
            followed = False
            committed = False
            tgt = _target_number(self.goal) if self.goal else None
            # Say in words whether the target is inside each range. The
            # chooser got this wrong three passes running ("T101-T126 does
            # not include T111") and walked 40 m back out of the right
            # corridor on the strength of it.
            verdicts = []
            for e in ents:
                rng = _parse_label_range(e['label'])
                if rng is None or rng[1] == rng[2] or not tgt:
                    continue
                if _range_has(rng, tgt):
                    verdicts.append(f"Room {self.goal} IS inside '{e['label']}': this sign is FOR your target"
                                    + (f" -- the corridor through the opening its {e['arrow']} arrow points at is the one to walk"
                                       if e['arrow'] in ('left', 'right', 'up') else ''))
                else:
                    verdicts.append(f"Room {self.goal} is NOT inside '{e['label']}'")
            if verdicts:
                line += "\n      " + ". ".join(verdicts) + "."
            for e in ents:
                rng = _parse_label_range(e['label'])
                if rng is None or not (tgt and _range_has(rng, tgt)):
                    continue
                for v in keypoints_dict.values():
                    room = v.get('room') if isinstance(v, dict) else None
                    rr = _parse_label_range(room) if room else None
                    if rr and _range_has(rng, (rr[0], rr[1])):
                        followed = True
                        break
                if followed:
                    break
                # No plate read yet, but the rig has gone well through the
                # opening the arrow named (8 m+ from the sign, on the arrow's
                # side): it is committed to that corridor. Before this the
                # corridor rule and Frontier_ahead only kicked in after the
                # first plate, and when the frontier at the far end blinked
                # out the chooser had nothing ahead and picked one 19 m back.
                if e['arrow'] in ('left', 'right') and view.get('robot_xy') and dist >= 8.0:
                    vx_, vy_ = sx - view['robot_xy'][0], sy - view['robot_xy'][1]
                    nv_ = math.hypot(vx_, vy_)
                    if nv_ > 0.3:
                        vx_, vy_ = vx_ / nv_, vy_ / nv_
                        lx2, ly2 = -vy_, vx_                              # photographer's LEFT
                        lat_ = (rx - sx) * lx2 + (ry - sy) * ly2
                        if (lat_ >= 3.0) == (e['arrow'] == 'left') and abs(lat_) >= 3.0:
                            committed = True
            if followed or committed:
                if followed:
                    line += ("\n      You have ALREADY followed this sign: room numbers you read are inside "
                             "its range, so you are in the corridor it points into. It has done its job "
                             "and names no further opening. Going back towards it is wrong. Use the "
                             "corridor block below instead.")
                else:
                    line += ("\n      You have ALREADY gone through the opening this sign pointed at and are "
                             "walking the corridor it meant. Keep going along it and read its doors; going "
                             "back towards the sign is wrong. Use the corridor block below.")
                if self._corridor is not None:
                    self._corridor['followed_sign'] = True
                sides = None
            else:
                sides = self._sign_sides(sx, sy, reader, keypoints_dict, kp)
            if sides is not None:
                parts = []
                for side in ('LEFT', 'RIGHT'):
                    items = sides[side]
                    txt = f"{side}: " + (", ".join(t for *_, t in items[:3]) if items else "nothing left to visit there")
                    read = sides[side + '_read']
                    if read:
                        txt += " (already read on that side, do not go back: " + ", ".join(r for _, r in read) + ")"
                    parts.append(txt)
                line += ("\n      For the person who took that photo, facing the sign -- "
                         + "; ".join(parts) + ". Only places still worth going to are listed; "
                         "visited doors and anything already behind you are left out.")
            lines.append(line)
        for l in lines:
            self.get_logger().info('[sign] ' + l.replace('\n', ' '))
        return images, lines

    def vlm_choose_next_pose(self, target:str, costmap_image, keypoints_dict):
        vlm_keypt_dict = prepare_landmarks_dict_for_vlm(keypoints_dict, ABLATION)
        # Where each landmark is relative to the rig, in words. Index numbers
        # are identifiers, but the VLM read them as positions ("landmark 7 is
        # between 6 and 8") and sent the carrier 34 m back down the corridor.
        # Nothing left to go to: asking the VLM only produces a Visited_ pick
        # and a re-ask, 98 times in one replay. Wait for the map to grow.
        if not any(str(v.get('name', '')).startswith(('Unvisited_', 'Frontier'))
                   for v in keypoints_dict.values() if isinstance(v, dict)):
            self.get_logger().info('no unvisited landmark or frontier on the map -- waiting')
            time.sleep(2.0)
            raise ValueError('nothing to go to yet')
        corridor_lines = self._corridor_context(keypoints_dict, target)
        if self.robot_pose is not None:
            rx, ry, ryaw = pose_msg_to_xyyaw(self.robot_pose)
            # "ahead" = the way the rig has been walking, not the way the
            # carrier happens to be facing while they look at a door.
            ax = self._travel_axis()
            if ax is not None and ax[2]:
                ryaw = math.atan2(ax[1], ax[0])
            for k, v in vlm_keypt_dict.items():
                if isinstance(v, dict) and 'position' in v:
                    dx, dy = v['position'][0] - rx, v['position'][1] - ry
                    dist = math.hypot(dx, dy)
                    rel = (math.degrees(math.atan2(dy, dx) - ryaw) + 180.0) % 360.0 - 180.0
                    sec = ['ahead', 'ahead-left', 'left', 'behind-left', 'behind',
                           'behind-right', 'right', 'ahead-right'][int(((rel + 22.5) % 360.0) // 45.0)]
                    v['from_you'] = f"{dist:.0f} m {sec}"
        sign_images, sign_lines = ([], [])
        if ABLATION != 1:
            sign_images, sign_lines = self._sign_context(keypoints_dict)
        for l in corridor_lines:
            self.get_logger().info('[corridor] ' + l)
        # Landmarks inside the ruled-out corridor leave the JSON altogether:
        # listed, they were picked seven times in one replay and refused seven
        # times, a VLM round trip each. The map image still shows their stars,
        # but the VLM chooses by JSON index.
        ro = getattr(self, '_ruled_out', None)
        if ro and ro['keys']:
            for k in list(vlm_keypt_dict.keys()):
                if k in ro['keys']:
                    del vlm_keypt_dict[k]
        prompt = VLMPrompts.choose_next_landmark_prompt(
            target, vlm_keypt_dict, sign_lines, corridor_lines)
        if getattr(self, '_vlm_feedback', None):
            prompt += "\n\n" + self._vlm_feedback
        if ABLATION == 1: # ablation for no map
            vlm_result = self.vlm_client.text_query_vlm(prompt)
        else:
            vlm_result = self.vlm_client.images_text_query_vlm(
                [costmap_image] + sign_images, prompt)
        # list the frontiers and landmarks in the prompt as well, just using json string
        landmark_names = [(i, keypoints_dict[i]['name']) for i in range(len(keypoints_dict))]
        self.get_logger().info(f"VLM Choice: {vlm_result}")

        # "Chosen landmarks: [3], [5], [1]" -- everything bracketed after the
        # last "Chosen landmark" phrase, in order, deduplicated, valid indices
        # only. The first is acted on now; the rest go into plan_queue so the
        # carrier is not stood waiting on a VLM round trip after every arrival.
        tail = vlm_result
        m = list(re.finditer(r'chosen landmarks?', vlm_result, re.I))
        if m:
            tail = vlm_result[m[-1].end():]
        else:
            # No "Chosen landmarks:" phrase. The answer format puts the pick on
            # the last line; every other bracket is a landmark being *talked
            # about*. Taking them all in order once read "The sign at [14]
            # covers ... go to door [13]" as "go to the sign" and walked the
            # carrier 28 m back to it.
            last = [l for l in vlm_result.strip().splitlines() if l.strip()]
            tail = last[-1] if last else vlm_result
            if not re.search(r'\[\s*\d+', tail):
                allb = re.findall(r'\[\s*(\d+)', vlm_result)
                tail = f'[{allb[-1]}]' if allb else ''
        picks, rejected = [], []
        # "[3], [5]" and also "[3, 5]" / "**[7, 4]**": every integer inside
        # any bracket group, in order.
        toks = [t for grp in re.findall(r'\[([\d,\s]+)\]', tail) for t in re.findall(r'\d+', grp)]
        for tok in toks:
            i = int(tok)
            if i not in keypoints_dict or i in picks or 'robot' in keypoints_dict[i].get('name', ''):
                continue
            # A visited door is not a destination. Silently swapping it for the
            # nearest unvisited thing sent the carrier to whatever happened to be
            # close -- a frontier behind them. Drop it here and, if nothing is
            # left, ask again with the mistake spelled out.
            if str(keypoints_dict[i].get('name', '')).startswith('Visited_'):
                rejected.append(i)
                continue
            picks.append(i)
        if not picks and not rejected:
            # "Chosen landmarks: [ ]" -- the answer named nothing. Say so in
            # the re-ask instead of tripping over int(' ').
            m0 = re.search(r'\[\s*(\d+)\s*\]', vlm_result)
            if m0 and int(m0.group(1)) in keypoints_dict:
                picks = [int(m0.group(1))]
            else:
                self._vlm_feedback = ("Your previous answer named no landmark index. End with "
                                      "'Chosen landmarks: [i]' where i is a number from the map list.")
                raise ValueError('VLM named no landmark')
        if rejected:
            self.get_logger().info(
                "VLM named visited landmark(s) " + ", ".join(f"[{i}]" for i in rejected) + " -- dropped")
        if not picks:
            self._visited_rejects = getattr(self, '_visited_rejects', 0) + 1
            if self._visited_rejects <= CORRIDOR_REASKS:
                self._vlm_feedback = (
                    "Your previous answer chose " + ", ".join(f"[{i}]" for i in rejected)
                    + ", which is a Visited_ door whose number is already known. That is not a "
                    "destination. Choose only Unvisited_ landmarks or Frontiers, ahead of you.")
                self.vlm_text_pub.publish(String(data=vlm_result + "\n[rejected: visited landmark, asking again]"))
                raise ValueError('VLM chose only visited landmarks')
            # Twice was enough: take the nearest thing still worth going to,
            # ahead first, instead of asking a third time.
            rx0, ry0, yaw0 = pose_msg_to_xyyaw(self.robot_pose)
            ax0 = self._travel_axis()
            if ax0 is not None and ax0[2]:
                yaw0 = math.atan2(ax0[1], ax0[0])
            alts = [(k, v) for k, v in keypoints_dict.items()
                    if str(v.get('name', '')).startswith(('Unvisited_', 'Frontier')) and 'position' in v
                    and not recently_abandoned(*v['position'][:2])]
            def _rank(kv):
                dx, dy = kv[1]['position'][0] - rx0, kv[1]['position'][1] - ry0
                return (0 if dx * math.cos(yaw0) + dy * math.sin(yaw0) > 0 else 1, math.hypot(dx, dy))
            k0 = min(alts, key=_rank)[0]
            picks = [k0]
            self.get_logger().info(f"VLM kept naming visited landmarks; taking {keypoints_dict[k0]['name']} [{k0}]")
            self.vlm_text_pub.publish(String(data=vlm_result + f"\n[visited pick twice; going to the nearest unvisited landmark instead. Chosen landmark: [{k0}]]"))
        else:
            self._visited_rejects = 0
        # Ruled-out corridor: a sign range that holds the plates read there but
        # not the target. Picks inside it are refused like visited ones.
        ro = getattr(self, '_ruled_out', None)
        if ro and ro['keys']:
            bad = [i for i in picks if i in ro['keys']]
            picks = [i for i in picks if i not in ro['keys']]
            if bad:
                self.get_logger().info("ruled-out corridor: dropped " + ", ".join(f"[{i}]" for i in bad))
            if not picks:
                self._ruled_rejects = getattr(self, '_ruled_rejects', 0) + 1
                alts = [(k, v) for k, v in keypoints_dict.items()
                        if str(v.get('name', '')).startswith(('Unvisited_', 'Frontier')) and 'position' in v
                        and k not in ro['keys'] and not recently_abandoned(*v['position'][:2])]
                if self._ruled_rejects <= CORRIDOR_REASKS and alts:
                    self._vlm_feedback = (
                        "Your previous answer chose " + ", ".join(f"[{i}]" for i in bad)
                        + f", which lies INSIDE the corridor ruled out by the sign '{ro['label']}' (it does not "
                        f"contain {target}). Choose a landmark outside that corridor.")
                    self.vlm_text_pub.publish(String(data=vlm_result + "\n[rejected: inside the ruled-out corridor, asking again]"))
                    raise ValueError('VLM chose only landmarks inside the ruled-out corridor')
                if not alts:
                    # Everything outside was visited lately -- that is still
                    # better than the corridor we know is wrong. Take the
                    # nearest thing outside regardless of the visited radius.
                    alts = [(k, v) for k, v in keypoints_dict.items()
                            if str(v.get('name', '')).startswith(('Unvisited_', 'Frontier')) and 'position' in v
                            and k not in ro['keys']]
                if alts:
                    rx0, ry0, _ = pose_msg_to_xyyaw(self.robot_pose)
                    k0 = min(alts, key=lambda kv: math.hypot(kv[1]['position'][0] - rx0, kv[1]['position'][1] - ry0))[0]
                    picks = [k0]
                    self.get_logger().info(f"ruled-out corridor: taking {keypoints_dict[k0]['name']} [{k0}] instead")
                    self.vlm_text_pub.publish(String(data=vlm_result + f"\n[inside the ruled-out corridor; going to the nearest landmark outside it. Chosen landmark: [{k0}]]"))
                else:
                    # Nothing at all outside the ruled-out corridor: do not walk
                    # into it. Wait for the map to grow instead.
                    self.get_logger().info('ruled-out corridor: no candidate outside it -- waiting')
                    self.vlm_text_pub.publish(String(data=vlm_result + "\n[every candidate is inside the ruled-out corridor; waiting for new frontiers]"))
                    time.sleep(3.0)
                    raise ValueError('only ruled-out candidates on the map')
            else:
                self._ruled_rejects = 0
        # A sign nobody has read yet, within reach, comes first: a sign settles
        # more than any door, and reading it from 6 m away has produced
        # "T131-T150" for a T101-T126 sign and "7101-7124" for another.
        if self.robot_pose is not None:
            rx1, ry1, _ = pose_msg_to_xyyaw(self.robot_pose)
            sdb = self.landmark_db.landmark_db.get('a directional sign')
            unread = []
            for k, v in keypoints_dict.items():
                nm = str(v.get('name', ''))
                if not nm.startswith('Unvisited_directional sign') or 'position' not in v:
                    continue
                try:
                    sidx = int(nm.rsplit('_', 1)[-1])
                except ValueError:
                    continue
                view = self.sign_views.get(sidx)
                if view and (view.get('entries') or view.get('not_sign')):
                    continue                          # already read, or not a sign at all
                if sidx in getattr(self, '_sign_approached', set()):
                    continue                          # been there once already
                d = math.hypot(v['position'][0] - rx1, v['position'][1] - ry1)
                # (No recently_abandoned test here: reaching the frontier next
                # to the sign put the sign inside that 2 m radius and this
                # rule never fired.)
                if d <= SIGN_APPROACH_M:
                    unread.append((d, k))
            if unread and picks and picks[0] != min(unread)[1]:
                d0, k0 = min(unread)
                self.get_logger().info(f"sign first: {keypoints_dict[k0]['name']} {d0:.0f} m away is unread -- reading it before {keypoints_dict[picks[0]]['name']}")
                self.vlm_text_pub.publish(String(data=vlm_result + f"\n[unread sign {d0:.0f} m away: reading it first. Chosen landmark: [{k0}]]"))
                picks = [k0] + [p for p in picks if p != k0]
        # Door sweep. Walking a corridor, take its doors in order; the far
        # frontier comes after them. A frontier picked while an unvisited door
        # lies ahead within 20 m is swapped for the nearest such door -- that
        # is what sent the rig forward past doors and back again.
        cor = self._corridor
        if cor and (cor.get('followed_sign') or cor.get('predict') == 'ahead') and picks:
            # An unread door within a few metres is read first, whichever way
            # it lies. The numbers put T142 "3 m ahead" (west) while its own
            # unread door stood 3 m east; the rig walked 12 m west to the next
            # door, twice, before coming back to it.
            rx0, ry0, _ = pose_msg_to_xyyaw(self.robot_pose)
            retried = getattr(self.landmark_handlers, '_door_retry', set())
            def _door_idx(nm):
                try:
                    return int(str(nm).rsplit('_', 1)[-1])
                except ValueError:
                    return -1
            # A door just passed is still being read by the passive reader;
            # turning round for it two seconds later is the "pass it, then
            # come back" the carrier complained about. Behind the rig only
            # doors within 2.5 m qualify; ahead, within 6 m (3 m if already
            # approached once).
            def _near_ok(v):
                d_ = math.hypot(v['position'][0] - rx0, v['position'][1] - ry0)
                al_ = (v['position'][0] - rx0) * cor['ux'] + (v['position'][1] - ry0) * cor['uy']
                lim = 3.0 if _door_idx(v['name']) in retried else 6.0
                if al_ < -1.0:
                    # 4 m, not 2.5: door 7 was first detected 3 m behind the
                    # rig and so fell through, to be walked back to from 11 m.
                    lim = min(lim, 4.0)
                return d_ <= lim
            near = sorted((math.hypot(v['position'][0] - rx0, v['position'][1] - ry0), k)
                          for k, v in keypoints_dict.items()
                          if str(v.get('name', '')).startswith('Unvisited_door') and 'position' in v
                          and _near_ok(v)
                          and not recently_abandoned(*v['position'][:2]))
            if near and picks[0] != near[0][1]:
                d0, k0 = near[0]
                self.get_logger().info(
                    f"door sweep: {keypoints_dict[k0]['name']} is {d0:.0f} m away and unread -- reading it before {keypoints_dict[picks[0]]['name']}")
                self.vlm_text_pub.publish(String(data=vlm_result + f"\n[door sweep: unread door {d0:.0f} m away first. Chosen landmark: [{k0}]]"))
                picks = [k0] + [p for p in picks if p != k0]
            est_ = cor.get('est')
            fa = [k for k, v in keypoints_dict.items() if str(v.get('name', '')) == 'Frontier_ahead']
            if est_ is not None and fa and str(keypoints_dict[picks[0]].get('name', '')).startswith('Frontier') and picks[0] != fa[0]:
                p0 = keypoints_dict[picks[0]]['position']
                al0 = (p0[0] - cor['rx']) * cor['ux'] + (p0[1] - cor['ry']) * cor['uy']
                if al0 > est_ + 4.0:
                    self.get_logger().info(
                        f"door sweep: frontier {al0:.0f} m ahead overshoots the predicted spot ({est_:.0f} m) -- stopping there instead")
                    self.vlm_text_pub.publish(String(data=vlm_result + f"\n[the target should be ~{est_:.0f} m ahead; walking to that spot first. Chosen landmark: [{fa[0]}]]"))
                    picks = [fa[0]] + [p for p in picks if p != fa[0]]
            doors_ahead = sorted((a, k) for a, k in cor['ahead']
                                 if 'door' in str(keypoints_dict[k].get('name', '')) and a <= 20.0)
            if doors_ahead and str(keypoints_dict[picks[0]].get('name', '')).startswith('Frontier'):
                a0, k0 = doors_ahead[0]
                self.get_logger().info(
                    f"door sweep: frontier {keypoints_dict[picks[0]]['name']} picked with "
                    f"{keypoints_dict[k0]['name']} {a0:.0f} m ahead -- door first")
                self.vlm_text_pub.publish(String(data=vlm_result + f"\n[door sweep: reading {keypoints_dict[k0]['name']} first. Chosen landmark: [{k0}]]"))
                picks = [k0] + [p for p in picks if p != k0]
        # Corridor rule. Inside a corridor a sign sent us into, or one whose
        # numbers say the target is further on, a pick well behind the rig is
        # refused while anything unvisited lies ahead. Asked twice with the
        # mistake spelled out; then the nearest thing ahead is taken.
        # Only FRONTIERS behind the rig are refused, and only when the read
        # numbers actually place the target ahead. An unread door is never
        # refused wherever it is: reading the doors as we pass is the point,
        # and going back a few metres for one can be exactly right.
        cor = self._corridor
        # Frontier_ahead (the corridor continuing in front of the rig) counts
        # as something ahead: with it the only thing on offer, the chooser
        # still walked 28 m back to an unreadable door.
        ahead_list = list(cor['ahead']) if cor else []
        if cor and not ahead_list:
            fa_ = [k for k, v in keypoints_dict.items() if str(v.get('name', '')) == 'Frontier_ahead']
            if fa_:
                ahead_list = [(5.0, fa_[0])]
        if cor and cor.get('predict') == 'ahead' and ahead_list:
            # A door well behind is refused too, but only while the numbers
            # put the target close ahead and something unvisited is there to
            # check first. Door 7 was detected 3 m after the rig passed it;
            # with T143 just read and T142 due 2 m further on, the chooser
            # walked 11 m back for door 7 and then 11 m forward again. Once
            # the stretch ahead is checked (nothing left there), the door
            # behind is a valid pick again.
            est_ = cor.get('est')
            check_ahead_first = (est_ is not None and est_ <= 40.0
                                 and any(a <= est_ + 6.0 for a, _ in ahead_list))
            kept, back = [], []
            for i in picks:
                v = keypoints_dict[i]
                nm_ = str(v.get('name', ''))
                if 'position' in v and (nm_.startswith('Frontier') or (check_ahead_first and nm_.startswith('Unvisited_door'))):
                    along = ((v['position'][0] - cor['rx']) * cor['ux']
                             + (v['position'][1] - cor['ry']) * cor['uy'])
                    # A door just passed (within the 4 m the door sweep
                    # itself turns round for) is never refused.
                    dist_ = math.hypot(v['position'][0] - cor['rx'], v['position'][1] - cor['ry'])
                    if nm_.startswith('Unvisited_door') and dist_ <= 4.0:
                        kept.append(i)
                        continue
                    if along < -CORRIDOR_BACK_M:
                        back.append((i, along))
                        continue
                kept.append(i)
            if back:
                self.get_logger().info(
                    "corridor rule: dropped " + ", ".join(f"[{i}] ({-a:.0f} m behind)" for i, a in back))
            if not kept:
                self._corridor_rejects += 1
                if self._corridor_rejects <= CORRIDOR_REASKS:
                    self._vlm_feedback = (
                        "Your previous answer chose " + ", ".join(f"[{i}]" for i, _ in back)
                        + ", which is BEHIND you, while the door numbers place the target close AHEAD "
                        "(see the corridor block). Check the stretch ahead first: choose from the AHEAD list"
                        + (", or an unread door within a few metres." if check_ahead_first else ", or an unread door."))
                    self.vlm_text_pub.publish(String(data=vlm_result + "\n[rejected: behind you in this corridor, asking again]"))
                    raise ValueError('VLM chose only landmarks behind the rig')
                doors = [(a, k) for a, k in ahead_list if 'door' in str(keypoints_dict[k]['name'])]
                a, k = min(doors or ahead_list)
                if a > 30.0:
                    # Nothing ahead within reason: the axis may be wrong. Let
                    # the VLM's own pick stand rather than send the carrier
                    # 46 m to a frontier that was "ahead" only on paper.
                    self.get_logger().info(f"corridor rule: nearest ahead is {a:.0f} m away -- not overriding")
                    kept = picks
                else:
                    kept = [k]
                if kept == [k]:
                    self.get_logger().info(f"corridor rule: VLM kept looking back; taking {keypoints_dict[k]['name']} [{k}] {a:.0f} m ahead")
                    self.vlm_text_pub.publish(String(data=
                        vlm_result + f"\n[corridor rule: that is behind you; going to the nearest unvisited landmark ahead instead. Chosen landmark: [{k}]]"))
            picks = kept
        self._corridor_rejects = 0
        self._vlm_feedback = None
        landmark_index = picks[0]
        self.plan_queue = [dict(keypoints_dict[i]) for i in picks[1:PLAN_MAX]]
        if self.plan_queue:
            self.get_logger().info("PLAN after this: " + " -> ".join(q['name'] for q in self.plan_queue))
        self.get_logger().info(f"VLM Picked Landmark {landmark_names[landmark_index]}, with reason {vlm_result}")
        
        vlm_result_msg = String()
        vlm_result_msg.data = vlm_result
        self.vlm_text_pub.publish(vlm_result_msg)
        json_msg = String()
        json_msg.data = str(keypoints_dict)
        self.landmark_json_pub.publish(json_msg)
        return vlm_result, keypoints_dict[landmark_index]


def main():
    rclpy.init()
    node = VLMNav()
    node.get_logger().info("Start...")
    node.goal = GOAL
    node.hri_agent.goal = GOAL
    node.get_logger().info(f"HRI Goal: {node.hri_agent.get_goal()}")
    # Hand nav_utils a live pose so its handheld "walk there yourself" wait can
    # tell when the carrier has actually arrived.
    attach_pose_source(node)
    navigator = BasicNavigator()
    executor = rclpy.executors.MultiThreadedExecutor()
    executor.add_node(node)
    executor.add_node(navigator)
    # Run ROS 2 spinning in a separate thread
    spin_thread = threading.Thread(target=executor.spin, daemon=True)
    spin_thread.start()
    # change detection back to default query
    default_query = String()
    default_query.data = DEFAULT_DET_QUERY
    default_thresh = Float32MultiArray()
    default_thresh.data = DEFAULT_DET_THRESH
    node.det_query_pub.publish(default_query)
    node.det_thresh_pub.publish(default_thresh)
    time.sleep(2)
    # The opening 360-degree spin is a robot-base behaviour: it drives nav2's
    # /spin action to sweep the surroundings into the costmap. A handheld rig
    # has no base (and we run no behavior_server), so the action would never be
    # served and this would block forever -- you sweep the room by walking.
    if os.environ.get('REASONNAV_NO_SPIN'):
        node.get_logger().info('REASONNAV_NO_SPIN set: skipping the initial spin.')
    else:
        node.get_logger().info("Sending manual navigation goal from main thread...")
        spin_wait(navigator, 6.28)
        time.sleep(6.0)

    while(node.robot_pose is None):
        time.sleep(1.0)

    # try:
    last_pass = 0.0
    while rclpy.ok():
        # Pace from the start of the previous pass, so slow passes are not
        # penalised twice.
        idle = LOOP_MIN_PERIOD - (time.monotonic() - last_pass)
        if idle > 0:
            time.sleep(idle)
        last_pass = time.monotonic()

        # The costmap subscription, not the nav2 service. getGlobalCostmap()
        # spins the navigator node from this thread while the executor spins
        # it too, and that race surfaced as "wait set index too big" at the
        # first call of a run, killing vlm_nav before its first decision.
        costmap = node.costmap
        if costmap is None:
            # Say so: a replay once sat here silently for the whole bag after
            # nav2's costmap failed to activate (TF timeout on sim time).
            node.get_logger().warn('waiting for /global_costmap/costmap -- no costmap received yet',
                                   throttle_duration_sec=10.0)
            # nav2 gives up activating the costmap when the TF tree is not yet
            # visible to it at start-up and never tries again. After 15 s
            # without a costmap, ask the lifecycle manager to RESUME (activate
            # the configured-but-inactive planner_server); repeat every 15 s.
            t_wait0 = getattr(node, '_costmap_wait_t0', None)
            if t_wait0 is None:
                node._costmap_wait_t0 = time.monotonic()
            elif time.monotonic() - t_wait0 > 15.0:
                node._costmap_wait_t0 = time.monotonic()
                try:
                    from nav2_msgs.srv import ManageLifecycleNodes
                    cli = node.create_client(ManageLifecycleNodes, '/lifecycle_manager_handheld/manage_nodes')
                    if cli.wait_for_service(timeout_sec=2.0):
                        req = ManageLifecycleNodes.Request(); req.command = ManageLifecycleNodes.Request.RESUME
                        fut = cli.call_async(req)
                        t1 = time.monotonic()
                        while not fut.done() and time.monotonic() - t1 < 10.0:
                            time.sleep(0.2)
                        node.get_logger().warn(
                            f"asked nav2 lifecycle manager to RESUME (costmap activation retry): "
                            f"{'ok' if fut.done() and fut.result() and fut.result().success else 'no success'}")
                    else:
                        node.get_logger().warn('lifecycle manager service not available for costmap retry')
                    node.destroy_client(cli)
                except Exception as e:
                    node.get_logger().warn(f'costmap activation retry failed: {e}')
            time.sleep(0.5)
            continue

        while node.goal is None:
            while "a person" not in node.landmark_db.landmark_db:
                time.sleep(1.0)
            node.hri_agent.initiate(None, None)
            node.goal = node.hri_agent.get_goal()
            # decide if web search
            if node.goal:
                did_search = node.vlm_web_search()
                if "true" in did_search.lower():
                    # get room # from "bldg room#""
                    goal_tmp = node.goal.split()
                    node.goal = goal_tmp[-1]

        # The 1 Hz refresh timer has almost always just done this; reuse it.
        cache = getattr(node, '_frontier_cache', None)
        if cache is not None and time.monotonic() - cache[0] < FRONTIER_REUSE_S:
            frontier_results = cache[1]
        else:
            frontier_results = get_frontiers_with_filtering(
                costmap, node.robot_pose, node.tf_buffer, FOOTPRINT_POLYGON,
                config, node, node.marker_pub
            )

        frontier_dict = {} # name -> position_xy
        if frontier_results[1] is not None:
            _, f_world_pose = frontier_results
            for pose in f_world_pose:
                # Drop frontiers we already walked at and could not reach.
                # They are recomputed from scratch every pass, so without this
                # the chooser can name the same dead end forever.
                if recently_abandoned(pose.position.x, pose.position.y) and \
                        not node._ahead_in_corridor(pose.position.x, pose.position.y):
                    continue
                # Carry the yaw: it is the outward normal into the unknown,
                # computed where the boundary is still in hand. Recomputing it
                # downstream from the robot's position throws that away.
                _, _, fyaw = pose_msg_to_xyyaw(pose)
                frontier_dict[f"Frontier_{len(frontier_dict)}"] = {
                    'position_xy': [pose.position.x, pose.position.y],
                    'yaw': fyaw,
                }
        # Hand the frontiers to the timer so its renders stay in sync with the
        # loop's view even while a handler is running.
        landmarks_dict = node.landmark_db.get_landmarks_dict()
        fw = node._forward_waypoint(frontier_dict, landmarks_dict)
        if fw is not None:
            frontier_dict['Frontier_ahead'] = {'position_xy': [fw[0], fw[1]], 'yaw': fw[2]}
            node.get_logger().info(f'corridor: nothing unvisited ahead -- offering Frontier_ahead at ({fw[0]:.1f}, {fw[1]:.1f})')
        node.last_frontier_dict = frontier_dict

        # RViz gets exactly this list -- the one the VLM is about to choose
        # from -- and nothing else. Two things used to make the arrows there
        # disagree with the stars on the landmark map: markers were published
        # upstream, before the abandoned/visited filter; and nothing ever
        # deleted an old one, so when the count fell from nine to five the
        # last four sat on screen indefinitely, pointing at places no longer
        # reachable. DELETEALL first, then the current set.
        node._publish_frontier_markers(frontier_dict)
        costmap_image, keypoints_dict = vis_landmarks(costmap, frontier_dict, landmarks_dict, node.robot_pose)
        node.pub_frontier_img(costmap_image)
        # node.get_logger().info(f"Keypoints Dict: {keypoints_dict}")

        # any() returns a bool, so this used to hand the VLM the literal string
        # "Room True" as its target. It stayed hidden while goal was an int and
        # the TypeError sent it down the except branch; the moment goal became a
        # string (T145) the bug became the only thing the VLM ever saw.
        goal_txt = str(node.goal).strip()
        # "Room 3018" reads better than a bare number, but a goal that is
        # already a phrase ("the kitchen") should be passed through as-is.
        nav_goal = (f"Room {goal_txt}"
                    if any(c.isdigit() for c in goal_txt) else goal_txt)
        node.get_logger().info(f"Keypoints Dict: {keypoints_dict}")

        # Choose next landmark using ablation utilities
        # A failed or timed-out query costs one pass, not the run. Before the
        # client had a timeout a single stalled request froze the loop here
        # indefinitely: the map and OCR timers carried on from their own
        # threads, so the stack looked alive while never choosing a goal again.
        next_landmark = node._next_planned(keypoints_dict)
        if next_landmark is None:
            try:
                _, next_landmark = choose_landmark_with_ablation(
                    node, ABLATION, keypoints_dict, nav_goal, costmap_image
                )
            except Exception as e:
                node.get_logger().warn(
                    f'landmark choice failed ({type(e).__name__}: {str(e)[:120]}); '
                    'retrying next pass')
                continue
        abandoned_before = len(nav_utils_module._ABANDONED)
        # The VLM keeps naming doors it has already inspected ("Visited_door_1",
        # twice in one run, both unreachable). A visited door is context, not a
        # destination: swap it for the nearest thing still worth going to.
        if str(next_landmark.get('name', '')).startswith('Visited_') and node.robot_pose is not None:
            rx_, ry_, _ = pose_msg_to_xyyaw(node.robot_pose)
            alts = [v for v in keypoints_dict.values()
                    if 'position' in v and (v['name'].startswith('Unvisited_') or v['name'].startswith('Frontier'))
                    and not recently_abandoned(*v['position'][:2])]
            if alts:
                # Prefer what lies ahead of the rig; nearest-overall picked a
                # frontier behind the carrier and undid twenty metres of corridor.
                _, _, yaw_ = pose_msg_to_xyyaw(node.robot_pose)
                def _rank(v):
                    dx_, dy_ = v['position'][0] - rx_, v['position'][1] - ry_
                    ahead = dx_ * math.cos(yaw_) + dy_ * math.sin(yaw_) > 0.0
                    return (0 if ahead else 1, math.hypot(dx_, dy_))
                alt = min(alts, key=_rank)
                node.get_logger().info(
                    f"VLM chose {next_landmark['name']} (already visited) -> going to {alt['name']} instead")
                next_landmark = alt
        node.get_logger().info(f"Chosen landmark {next_landmark['name']}")

        # A number read while walking past counts: no reason to keep exploring
        # once the target has already been seen.
        if node.goal_reached:
            node.get_logger().info(f"Room {node.goal} found in passing!")
            break

        landmark_pose = None
        if 'door' in next_landmark['name']:
            found = node.landmark_handlers.handle_door_landmark(navigator, next_landmark, landmark_pose, MAX_REPOSITION_ATTEMPTS, VLM_SIGN_DIR)
            if found:
                break

        elif 'frontier' in next_landmark['name'].lower():
            node.landmark_handlers.handle_frontier_landmark(navigator, next_landmark, frontier_dict)

        elif 'sign' in next_landmark['name'].lower():
            landmark_pose = node.landmark_db.get_landmark_pose(next_landmark['name']) if landmark_pose is None else landmark_pose
            node.landmark_handlers.handle_sign_landmark(navigator, next_landmark, landmark_pose, costmap_image, VLM_SIGN_DIR)

        elif 'person' in next_landmark['name'].lower():
            landmark_pose = node.landmark_db.get_landmark_pose(next_landmark['name']) if landmark_pose is None else landmark_pose
            node.landmark_handlers.handle_person_landmark(navigator, next_landmark, landmark_pose, costmap_image)
        if len(nav_utils_module._ABANDONED) > abandoned_before and node.plan_queue:
            node.get_logger().info('PLAN dropped: this step could not be reached')
            node.plan_queue = []


    # Cleanup
    node.destroy_node()
    navigator.destroy_node()
    rclpy.shutdown()
    spin_thread.join()

if __name__ == '__main__':
    main()