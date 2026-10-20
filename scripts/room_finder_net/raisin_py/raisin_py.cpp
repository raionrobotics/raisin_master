// raisin_py: minimal Python binding of raisin_network for the room finder (no ROS 2 anywhere).
//
//   net = raisin_py.Net("ai_pc", ["eth0"])               # raisin Network + server
//   conn = net.connect("robot_nickname")                 # None until the peer is up
//   net.subscribe_image(conn, "oak_front/rgb", cb)       # cb(stamp, frame_id, height, width, encoding, data:uint8[])
//   net.subscribe_odometry(conn, "/Odometry/base", cb)   # cb(stamp, frame_id, (x y z qx qy qz qw), (vx vy vz wx wy wz))
//   net.subscribe_cloud(conn, "cloud_registered", cb)    # cb(stamp, frame_id, points: float32[N,3])
//   net.subscribe_nav_status(conn, "navigation/status", cb)  # cb(has_goal, has_plan, current_index, waypoint_count)
//   net.subscribe_string(conn, topic, cb) / net.publisher_string(topic).publish(str)
//   net.subscribe_grid(conn, topic, cb)                  # cb(stamp, frame_id, resolution, x0, y0, int8[h,w])
//   net.publisher_grid(topic).publish(frame_id, resolution, x0, y0, int8[h,w])
//   net.service_string(name, fn)                         # fn(str) -> (bool, str)   (server side)
//   net.call_string(conn, name, data, timeout) -> (ok, msg);  call_trigger;  call_string_and_bool
//   net.call_set_waypoints(conn, name, [(frame, x, y, use_yaw, yaw)], timeout) -> (ok, msg)
// All callbacks run on raisin's thread pool with the GIL held; all blocking calls release the GIL.
#include <pybind11/pybind11.h>
#include <pybind11/numpy.h>
#include <pybind11/functional.h>
#include <pybind11/stl.h>

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "raisin_network/raisin.hpp"
#include "raisin_network/network.hpp"
#include "raisin_network/node.hpp"
#include "sensor_msgs/msg/image.hpp"
#include "sensor_msgs/msg/point_cloud2.hpp"
#include "nav_msgs/msg/odometry.hpp"
#include "nav_msgs/msg/occupancy_grid.hpp"
#include "std_msgs/msg/string.hpp"
#include "raisin_interfaces/msg/navigation_status.hpp"
#include "raisin_interfaces/msg/waypoint.hpp"
#include "raisin_interfaces/srv/set_waypoints.hpp"
#include "raisin_interfaces/srv/string.hpp"
#include "raisin_interfaces/srv/string_and_bool.hpp"
#include "std_srvs/srv/trigger.hpp"

namespace py = pybind11;
using Conn = std::shared_ptr<raisin::Remote::Connection>;

namespace {

double stamp_of(const raisin::std_msgs::msg::Header& h) { return h.stamp.sec + 1e-9 * h.stamp.nanosec; }

template <typename Fn>
void guarded(Fn&& fn) {
  py::gil_scoped_acquire gil;
  try {
    fn();
  } catch (py::error_already_set& e) {
    PyErr_Print();   // never let a Python exception unwind into raisin's thread pool
  }
}

template <typename R>
py::tuple reply(const std::shared_ptr<R>& res) {
  if (!res) return py::make_tuple(false, std::string("timeout"));
  return py::make_tuple((bool)res->success, std::string(res->message));
}

template <typename T>
struct PyPublisher {
  std::shared_ptr<raisin::Publisher<T>> pub;
};

template <typename Srv>
std::shared_ptr<typename Srv::Response> call(const std::shared_ptr<raisin::Client<Srv>>& client,
                                             std::shared_ptr<typename Srv::Request> req, double timeout) {
  py::gil_scoped_release release;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::duration<double>(timeout);
  while (!client->isServiceAvailable()) {
    if (std::chrono::steady_clock::now() > deadline) return nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  auto fut = client->asyncSendRequest(req);
  if (fut.wait_until(deadline) != std::future_status::ready) return nullptr;
  return fut.get();
}

}  // namespace

class Net {
 public:
  Net(const std::string& id, const std::vector<std::string>& ifnames) {
    raisin::raisinInit();
    std::vector<std::vector<std::string>> threads = {{"main"}};
    network_ = std::make_shared<raisin::Network>(id, "raisin_py", threads, ifnames);
    network_->launchServer();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    node_ = std::make_unique<raisin::Node>(network_);
  }
  ~Net() { close(); }

  void close() {
    if (node_) {
      py::gil_scoped_release release;
      node_->cleanupResources();
      node_.reset();
    }
    subs_.clear();
    clients_.clear();
    services_.clear();
  }

  Conn connect(const std::string& peer) {
    py::gil_scoped_release release;
    return network_->connect(peer);
  }

  // ---- subscribers ---------------------------------------------------------------------------
  void subscribe_image(Conn c, const std::string& topic, py::function cb) {
    keep(node_->createSubscriber<raisin::sensor_msgs::msg::Image>(
      topic, c, [cb](std::shared_ptr<raisin::sensor_msgs::msg::Image> m) {
        guarded([&] {
          py::array_t<uint8_t> data(m->data.size());
          std::memcpy(data.mutable_data(), m->data.data(), m->data.size());
          cb(stamp_of(m->header), m->header.frame_id, m->height, m->width, m->encoding, data);
        });
      }));
  }

  void subscribe_odometry(Conn c, const std::string& topic, py::function cb) {
    keep(node_->createSubscriber<raisin::nav_msgs::msg::Odometry>(
      topic, c, [cb](std::shared_ptr<raisin::nav_msgs::msg::Odometry> m) {
        guarded([&] {
          const auto& p = m->pose.pose;
          const auto& t = m->twist.twist;
          cb(stamp_of(m->header), m->header.frame_id,
             py::make_tuple(p.position.x, p.position.y, p.position.z, p.orientation.x, p.orientation.y,
                            p.orientation.z, p.orientation.w),
             py::make_tuple(t.linear.x, t.linear.y, t.linear.z, t.angular.x, t.angular.y, t.angular.z));
        });
      }));
  }

  void subscribe_cloud(Conn c, const std::string& topic, py::function cb) {
    keep(node_->createSubscriber<raisin::sensor_msgs::msg::PointCloud2>(
      topic, c, [cb](std::shared_ptr<raisin::sensor_msgs::msg::PointCloud2> m) {
        guarded([&] {
          int ox = -1, oy = -1, oz = -1;
          for (const auto& f : m->fields) {
            if (f.name == "x") ox = f.offset;
            if (f.name == "y") oy = f.offset;
            if (f.name == "z") oz = f.offset;
          }
          const size_t n = m->point_step ? m->data.size() / m->point_step : 0;
          if (ox < 0 || oy < 0 || oz < 0 || n == 0) return;
          py::array_t<float> pts({(py::ssize_t)n, (py::ssize_t)3});
          float* out = pts.mutable_data();
          for (size_t i = 0; i < n; ++i) {
            const uint8_t* p = m->data.data() + i * m->point_step;
            std::memcpy(out + 3 * i + 0, p + ox, 4);
            std::memcpy(out + 3 * i + 1, p + oy, 4);
            std::memcpy(out + 3 * i + 2, p + oz, 4);
          }
          cb(stamp_of(m->header), m->header.frame_id, pts);
        });
      }));
  }

  void subscribe_nav_status(Conn c, const std::string& topic, py::function cb) {
    keep(node_->createSubscriber<raisin::raisin_interfaces::msg::NavigationStatus>(
      topic, c, [cb](std::shared_ptr<raisin::raisin_interfaces::msg::NavigationStatus> m) {
        guarded([&] { cb(m->has_goal, m->has_plan, (int)m->current_index, (int)m->waypoint_count); });
      }));
  }

  void subscribe_string(Conn c, const std::string& topic, py::function cb) {
    keep(node_->createSubscriber<raisin::std_msgs::msg::String>(
      topic, c, [cb](std::shared_ptr<raisin::std_msgs::msg::String> m) { guarded([&] { cb(m->data); }); }));
  }

  void subscribe_grid(Conn c, const std::string& topic, py::function cb) {
    keep(node_->createSubscriber<raisin::nav_msgs::msg::OccupancyGrid>(
      topic, c, [cb](std::shared_ptr<raisin::nav_msgs::msg::OccupancyGrid> m) {
        guarded([&] {
          py::array_t<int8_t> g({(py::ssize_t)m->info.height, (py::ssize_t)m->info.width});
          if (m->data.size() == (size_t)m->info.height * m->info.width)
            std::memcpy(g.mutable_data(), m->data.data(), m->data.size());
          cb(stamp_of(m->header), m->header.frame_id, (double)m->info.resolution, m->info.origin.position.x,
             m->info.origin.position.y, g);
        });
      }));
  }

  // ---- publishers ----------------------------------------------------------------------------
  std::shared_ptr<PyPublisher<raisin::std_msgs::msg::String>> publisher_string(const std::string& topic) {
    auto p = std::make_shared<PyPublisher<raisin::std_msgs::msg::String>>();
    p->pub = node_->createPublisher<raisin::std_msgs::msg::String>(topic);
    return p;
  }

  std::shared_ptr<PyPublisher<raisin::nav_msgs::msg::OccupancyGrid>> publisher_grid(const std::string& topic) {
    auto p = std::make_shared<PyPublisher<raisin::nav_msgs::msg::OccupancyGrid>>();
    p->pub = node_->createPublisher<raisin::nav_msgs::msg::OccupancyGrid>(topic);
    return p;
  }

  // ---- services ------------------------------------------------------------------------------
  void service_string(const std::string& name, py::function fn) {
    using S = raisin::raisin_interfaces::srv::String;
    services_.push_back(node_->createService<S>(
      name, [fn](std::shared_ptr<S::Request> req, std::shared_ptr<S::Response> res) {
        guarded([&] {
          py::tuple r = fn(req->data);
          res->success = r[0].cast<bool>();
          res->message = r[1].cast<std::string>();
        });
      }));
  }

  py::tuple call_string(Conn c, const std::string& name, const std::string& data, double timeout) {
    using S = raisin::raisin_interfaces::srv::String;
    auto client = client_for<S>(c, name);
    auto req = std::make_shared<S::Request>();
    req->data = data;
    auto res = call<S>(client, req, timeout);
    return reply(res);
  }

  py::tuple call_trigger(Conn c, const std::string& name, double timeout) {
    using S = raisin::std_srvs::srv::Trigger;
    auto client = client_for<S>(c, name);
    auto res = call<S>(client, std::make_shared<S::Request>(), timeout);
    return reply(res);
  }

  py::tuple call_string_and_bool(Conn c, const std::string& name, const std::string& data, bool flag, double timeout) {
    using S = raisin::raisin_interfaces::srv::StringAndBool;
    auto client = client_for<S>(c, name);
    auto req = std::make_shared<S::Request>();
    req->data = data;
    req->flag = flag;
    auto res = call<S>(client, req, timeout);
    return reply(res);
  }

  py::tuple call_set_waypoints(Conn c, const std::string& name, const std::vector<py::tuple>& wps, double timeout) {
    using S = raisin::raisin_interfaces::srv::SetWaypoints;
    auto client = client_for<S>(c, name);
    auto req = std::make_shared<S::Request>();
    for (const auto& w : wps) {
      raisin::raisin_interfaces::msg::Waypoint wp;
      wp.frame = w[0].cast<std::string>();
      wp.x = w[1].cast<double>();
      wp.y = w[2].cast<double>();
      wp.z = 0.0;
      wp.use_z = false;
      wp.use_yaw = w[3].cast<bool>();
      wp.yaw = w[4].cast<double>();
      req->waypoints.push_back(wp);
    }
    req->repetition = 1;
    req->current_index = 0;
    req->infinite_loop = false;
    auto res = call<S>(client, req, timeout);
    return reply(res);
  }

 private:
  template <typename T>
  void keep(std::shared_ptr<T> s) { subs_.push_back(std::static_pointer_cast<void>(s)); }

  template <typename S>
  std::shared_ptr<raisin::Client<S>> client_for(Conn c, const std::string& name) {
    const std::string key = name + "|" + S::getDataType();
    auto it = clients_.find(key);
    if (it != clients_.end()) return std::static_pointer_cast<raisin::Client<S>>(it->second);
    auto cl = node_->createClient<S>(name, c);
    clients_[key] = std::static_pointer_cast<void>(cl);
    return cl;
  }

  std::shared_ptr<raisin::Network> network_;
  std::unique_ptr<raisin::Node> node_;
  std::vector<std::shared_ptr<void>> subs_, services_;
  std::map<std::string, std::shared_ptr<void>> clients_;
};

PYBIND11_MODULE(raisin_py, m) {
  m.doc() = "raisin_network for Python (room finder, no ROS 2)";
  py::class_<raisin::Remote::Connection, Conn>(m, "Connection");
  py::class_<PyPublisher<raisin::std_msgs::msg::String>, std::shared_ptr<PyPublisher<raisin::std_msgs::msg::String>>>(m, "StringPublisher")
    .def("publish", [](PyPublisher<raisin::std_msgs::msg::String>& p, const std::string& s) {
      raisin::std_msgs::msg::String msg;
      msg.data = s;
      py::gil_scoped_release release;
      p.pub->publish(msg);
    });
  py::class_<PyPublisher<raisin::nav_msgs::msg::OccupancyGrid>, std::shared_ptr<PyPublisher<raisin::nav_msgs::msg::OccupancyGrid>>>(m, "GridPublisher")
    .def("publish", [](PyPublisher<raisin::nav_msgs::msg::OccupancyGrid>& p, const std::string& frame, double res, double x0,
                       double y0, py::array_t<int8_t, py::array::c_style | py::array::forcecast> g) {
      raisin::nav_msgs::msg::OccupancyGrid msg;
      msg.header.frame_id = frame;
      auto now = std::chrono::system_clock::now().time_since_epoch();
      auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
      msg.header.stamp.sec = (int32_t)(ns / 1000000000LL);
      msg.header.stamp.nanosec = (uint32_t)(ns % 1000000000LL);
      msg.info.resolution = (float)res;
      msg.info.height = (uint32_t)g.shape(0);
      msg.info.width = (uint32_t)g.shape(1);
      msg.info.origin.position.x = x0;
      msg.info.origin.position.y = y0;
      msg.info.origin.orientation.w = 1.0;
      msg.data.assign(g.data(), g.data() + g.size());
      py::gil_scoped_release release;
      p.pub->publish(msg);
    });
  py::class_<Net>(m, "Net")
    .def(py::init<const std::string&, const std::vector<std::string>&>(), py::arg("id"), py::arg("interfaces") = std::vector<std::string>{})
    .def("close", &Net::close)
    .def("connect", &Net::connect)
    .def("subscribe_image", &Net::subscribe_image)
    .def("subscribe_odometry", &Net::subscribe_odometry)
    .def("subscribe_cloud", &Net::subscribe_cloud)
    .def("subscribe_nav_status", &Net::subscribe_nav_status)
    .def("subscribe_string", &Net::subscribe_string)
    .def("subscribe_grid", &Net::subscribe_grid)
    .def("publisher_string", &Net::publisher_string)
    .def("publisher_grid", &Net::publisher_grid)
    .def("service_string", &Net::service_string)
    .def("call_string", &Net::call_string, py::arg("conn"), py::arg("name"), py::arg("data"), py::arg("timeout") = 5.0)
    .def("call_trigger", &Net::call_trigger, py::arg("conn"), py::arg("name"), py::arg("timeout") = 30.0)
    .def("call_string_and_bool", &Net::call_string_and_bool, py::arg("conn"), py::arg("name"), py::arg("data"), py::arg("flag"), py::arg("timeout") = 30.0)
    .def("call_set_waypoints", &Net::call_set_waypoints, py::arg("conn"), py::arg("name"), py::arg("waypoints"), py::arg("timeout") = 5.0);
}
