"""rosless: just enough of rclpy and the ROS message packages for ReasonNav's room_perception.py / room_finder.py to run
WITHOUT ROS 2.

`install(router)` puts light stand-ins for `rclpy`, `sensor_msgs`, `std_msgs`, `geometry_msgs`, `nav_msgs`,
`visualization_msgs` and `tf2_ros` into sys.modules, so the two nodes are imported unchanged and their logic stays
identical to the ROS version.  What the stand-ins do:

  * Node         : parameters (overridable), logger, timers, subscriptions and publishers.  Like a ROS 2
                   single-threaded executor, all callbacks of one node run one after another on one thread;
                   a subscription keeps the latest `depth` messages only (an image that is not consumed in time is dropped).
  * messages     : plain Python objects with the fields the nodes touch (Markers accept any attribute).
  * tf2_ros      : Buffer.lookup_transform() answers from the router's pose model.
  * Router       : where topics go.  Topics without a registered route are an in-process bus (registry JSON between
                   perception and finder); the runner registers the ones that cross the network.
"""
import collections
import heapq
import itertools
import logging
import math
import sys
import threading
import time
import types

import numpy as np

# ---------------------------------------------------------------------------------------------------- messages


class _Loose:
    """object that creates nested attributes on demand (visualization markers are write-only for us)"""

    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        v = _Loose()
        self.__dict__[name] = v
        return v


class Stamp:
    def __init__(self, sec=0, nanosec=0):
        self.sec, self.nanosec = int(sec), int(nanosec)

    @staticmethod
    def from_seconds(t):
        t = float(t)
        return Stamp(int(t), int(round((t - int(t)) * 1e9)))

    def seconds(self):
        return self.sec + 1e-9 * self.nanosec


class Header:
    def __init__(self):
        self.stamp, self.frame_id = Stamp(), ""


class Point:
    def __init__(self, x=0.0, y=0.0, z=0.0):
        self.x, self.y, self.z = x, y, z


class Quaternion:
    def __init__(self, x=0.0, y=0.0, z=0.0, w=1.0):
        self.x, self.y, self.z, self.w = x, y, z, w


class Pose:
    def __init__(self):
        self.position, self.orientation = Point(), Quaternion()


class PoseStamped:
    def __init__(self):
        self.header, self.pose = Header(), Pose()


class ColorRGBA:
    def __init__(self, r=0.0, g=0.0, b=0.0, a=1.0):
        self.r, self.g, self.b, self.a = r, g, b, a


class String:
    def __init__(self, data=""):
        self.data = data


class Image:
    def __init__(self):
        self.header, self.height, self.width, self.encoding, self.step, self.data = Header(), 0, 0, "", 0, b""


class _MapInfo:
    def __init__(self):
        self.resolution, self.width, self.height, self.origin = 0.0, 0, 0, Pose()


class OccupancyGrid:
    def __init__(self):
        self.header, self.info, self.data = Header(), _MapInfo(), []


class Marker(_Loose):
    ARROW, CUBE, SPHERE, CYLINDER, LINE_STRIP, TEXT_VIEW_FACING = 0, 1, 2, 3, 4, 9
    ADD, DELETE, DELETEALL = 0, 2, 3

    def __init__(self):
        super().__init__(points=[], text="")


class MarkerArray:
    def __init__(self):
        self.markers = []


# ---------------------------------------------------------------------------------------------------- routing


class Router:
    """Decides where a topic goes.  Subclass / configure from the runner:
         sub_routes[topic] = fn(deliver)   -> starts feeding `deliver(msg)` from the network
         pub_routes[topic] = fn(msg)       -> sends a published message over the network
         pose_provider(frame, stamp) -> (xyz, quat_xyzw) in the map frame, or None
    """

    def __init__(self):
        self.sub_routes, self.pub_routes = {}, {}
        self.pose_provider = lambda frame, stamp: None
        self.local = collections.defaultdict(list)    # topic -> [deliver]
        self.lock = threading.Lock()

    def subscribe(self, topic, deliver):
        if topic in self.sub_routes:
            self.sub_routes[topic](deliver)
        else:
            with self.lock:
                self.local[topic].append(deliver)

    def publish(self, topic, msg):
        route = self.pub_routes.get(topic)
        if route is not None:
            route(msg)
            return
        with self.lock:
            subs = list(self.local.get(topic, ()))
        for deliver in subs:
            deliver(msg)


ROUTER = Router()

# ---------------------------------------------------------------------------------------------------- rclpy


class _Logger:
    def __init__(self, name):
        self._l = logging.getLogger(name)

    def info(self, m):
        self._l.info(m)

    def warn(self, m):
        self._l.warning(m)

    def error(self, m):
        self._l.error(m)

    def debug(self, m):
        self._l.debug(m)


class _Param:
    def __init__(self, value):
        self.value = value


class _Clock:
    class _Now:
        def __init__(self, t):
            self.t = t

        def to_msg(self):
            return Stamp.from_seconds(self.t)

        def nanoseconds(self):
            return int(self.t * 1e9)

    def now(self):
        return self._Now(time.time())


class QoSProfile:
    def __init__(self, depth=10, reliability=None, durability=None, **_):
        self.depth = depth


class _Enum:
    BEST_EFFORT = RELIABLE = VOLATILE = TRANSIENT_LOCAL = 0


class Time:
    def __init__(self, seconds=0.0):
        self.seconds = float(seconds)

    @staticmethod
    def from_msg(stamp):
        return Time(stamp.seconds() if isinstance(stamp, Stamp) else stamp.sec + 1e-9 * stamp.nanosec)


_SHUTDOWN = threading.Event()


def ok():
    return not _SHUTDOWN.is_set()


def init(*a, **k):
    _SHUTDOWN.clear()


def shutdown(*a, **k):
    _SHUTDOWN.set()


class Node:
    """single-threaded executor semantics: one worker thread runs this node's callbacks serially"""
    param_overrides = {}        # node name -> {param: value}, set by the runner before the node is created

    def __init__(self, name):
        self._rl_name = name
        self._rl_params = {}
        self._rl_overrides = dict(Node.param_overrides.get(name, {}))
        self._rl_log = _Logger(name)
        self._rl_cv = threading.Condition()
        self._rl_subs = []                 # [deque(maxlen=depth), callback]
        self._rl_timers = []               # heap of (due, seq, period, callback)
        self._rl_seq = itertools.count()
        self._rl_stop = False
        self._rl_clock = _Clock()
        self._rl_worker = threading.Thread(target=self._rl_run, name=name + "-executor", daemon=True)
        self._rl_worker.start()

    # --- ROS 2 Node API used by the nodes
    def declare_parameter(self, name, default=None):
        self._rl_params[name] = self._rl_overrides.get(name, default)
        return _Param(self._rl_params[name])

    def get_parameter(self, name):
        return _Param(self._rl_params[name])

    def get_logger(self):
        return self._rl_log

    def get_clock(self):
        return self._rl_clock

    def create_subscription(self, msg_type, topic, callback, qos=10, callback_group=None):
        depth = qos if isinstance(qos, int) else getattr(qos, "depth", 10)
        q = collections.deque(maxlen=max(1, depth))
        self._rl_subs.append((q, callback))

        def deliver(msg):
            with self._rl_cv:
                q.append(msg)
                self._rl_cv.notify()
        ROUTER.subscribe(topic, deliver)
        return q

    def create_publisher(self, msg_type, topic, qos=10):
        return _Publisher(topic)

    def create_timer(self, period, callback, callback_group=None):
        with self._rl_cv:
            heapq.heappush(self._rl_timers, (time.monotonic() + period, next(self._rl_seq), period, callback))
            self._rl_cv.notify()

    def destroy_node(self):
        with self._rl_cv:
            self._rl_stop = True
            self._rl_cv.notify()

    # --- executor
    def _rl_run(self):
        while True:
            work = None
            with self._rl_cv:
                while work is None:
                    if self._rl_stop or _SHUTDOWN.is_set():
                        return
                    for q, cb in self._rl_subs:
                        if q:
                            work = (cb, q.popleft())
                            break
                    if work is not None:
                        break
                    now = time.monotonic()
                    if self._rl_timers and self._rl_timers[0][0] <= now:
                        due, _, period, cb = heapq.heappop(self._rl_timers)
                        # skip missed periods instead of bursting
                        nxt = due + period
                        if nxt < now:
                            nxt = now + period
                        heapq.heappush(self._rl_timers, (nxt, next(self._rl_seq), period, cb))
                        work = (cb, None)
                        break
                    wait = (self._rl_timers[0][0] - now) if self._rl_timers else 1.0
                    self._rl_cv.wait(timeout=min(max(wait, 0.0), 1.0))
            cb, msg = work
            try:
                cb() if msg is None else cb(msg)
            except SystemExit:
                _SHUTDOWN.set()
                return
            except Exception:  # noqa: BLE001
                self._rl_log._l.exception("callback failed")


class _Publisher:
    def __init__(self, topic):
        self.topic = topic

    def publish(self, msg):
        try:
            ROUTER.publish(self.topic, msg)
        except Exception:  # noqa: BLE001
            logging.getLogger("rosless").exception("publish %s" % self.topic)


def spin(node=None):
    """block until shutdown (SystemExit raised by a node, Ctrl-C)"""
    try:
        while ok():
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------------------------------- tf2


class _Tf:
    def __init__(self, t, q):
        self.transform = _Loose(translation=Point(*t), rotation=Quaternion(*q))


class Buffer:
    def lookup_transform(self, target, source, time_=None):
        if target != "map":
            raise RuntimeError("only transforms into 'map' exist (asked %s <- %s)" % (target, source))
        stamp = None
        if time_ is not None and getattr(time_, "seconds", 0.0) > 0.0:
            stamp = time_.seconds
        r = ROUTER.pose_provider(source, stamp)
        if r is None:
            raise RuntimeError("no transform map <- %s" % source)
        return _Tf(*r)


class TransformListener:
    def __init__(self, buf, node):
        pass


# ---------------------------------------------------------------------------------------------------- install


def _mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    return m


def install(router=None):
    """make `import rclpy` etc. resolve to the stand-ins above (call before importing the nodes)"""
    global ROUTER
    if router is not None:
        ROUTER = router
        globals()["ROUTER"] = router
    me = sys.modules[__name__]
    rclpy_time = _mod("rclpy.time", Time=Time)
    rclpy = _mod("rclpy", ok=ok, init=init, shutdown=shutdown, spin=spin, time=rclpy_time)
    mods = {
        "rclpy": rclpy,
        "rclpy.time": rclpy_time,
        "rclpy.node": _mod("rclpy.node", Node=Node),
        "rclpy.qos": _mod("rclpy.qos", QoSProfile=QoSProfile, ReliabilityPolicy=_Enum, DurabilityPolicy=_Enum),
        "sensor_msgs": _mod("sensor_msgs"),
        "sensor_msgs.msg": _mod("sensor_msgs.msg", Image=Image),
        "std_msgs": _mod("std_msgs"),
        "std_msgs.msg": _mod("std_msgs.msg", String=String, ColorRGBA=ColorRGBA),
        "geometry_msgs": _mod("geometry_msgs"),
        "geometry_msgs.msg": _mod("geometry_msgs.msg", Point=Point, PoseStamped=PoseStamped),
        "nav_msgs": _mod("nav_msgs"),
        "nav_msgs.msg": _mod("nav_msgs.msg", OccupancyGrid=OccupancyGrid),
        "visualization_msgs": _mod("visualization_msgs"),
        "visualization_msgs.msg": _mod("visualization_msgs.msg", Marker=Marker, MarkerArray=MarkerArray),
        "tf2_ros": _mod("tf2_ros", Buffer=Buffer, TransformListener=TransformListener),
    }
    for k, v in mods.items():
        sys.modules[k] = v
    for pkg in ("sensor_msgs", "std_msgs", "geometry_msgs", "nav_msgs", "visualization_msgs"):
        sys.modules[pkg].msg = sys.modules[pkg + ".msg"]
    rclpy.node = mods["rclpy.node"]
    rclpy.qos = mods["rclpy.qos"]
    return me


def quat_to_yaw(q):
    return math.atan2(2 * (q.w * q.z + q.x * q.y), 1 - 2 * (q.y * q.y + q.z * q.z))
