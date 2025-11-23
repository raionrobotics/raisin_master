// Copyright (c) 2025 Raion Robotics Inc.
//
// Any unauthorized copying, alteration, distribution, transmission,
// performance, display or use of this material is prohibited.
//
// All rights reserved.

#ifndef RAISIN_EMPTY_PROCESS_PLUGIN__PUBLISHER_NODE_HPP_
#define RAISIN_EMPTY_PROCESS_PLUGIN__PUBLISHER_NODE_HPP_

#include <cstddef>
#include <string>
#include "std_msgs/msg/string.hpp"
#include "raisin_network/raisin.hpp"

namespace raisin
{
namespace empty_process
{

class PublisherNode
{
 public:
  PublisherNode(Node& node, double publishRateHz)
    : node_(node)
  {
    publisher_ = node_.createPublisher<std_msgs::msg::String>("my_topic");
    loopId_ = node_.createTimedLoop("publish_loop", [this]() {
      std_msgs::msg::String msg;
      msg.data = "hello world " + std::to_string(publishCount_++);
      publisher_->publish(msg);
    }, publishRateHz);
  }

 private:
  Node& node_;
  size_t publishCount_{0};
  uint32_t loopId_{0};
  Publisher<std_msgs::msg::String>::SharedPtr publisher_;
};

} // namespace empty_process
} // namespace raisin

#endif // RAISIN_EMPTY_PROCESS_PLUGIN__PUBLISHER_NODE_HPP_
