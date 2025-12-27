// Copyright (c) 2025 Raion Robotics Inc.
//
// Any unauthorized copying, alteration, distribution, transmission,
// performance, display or use of this material is prohibited.
//
// All rights reserved.
//

#include "std_msgs/msg/string.hpp"
#include "raisin_network/raisin.hpp"
#include <iostream>

using namespace raisin;

const char* shm_name = "my_shared_memory2";

class SubscriberNode : public raisin::Node
{
 public:
  explicit SubscriberNode(std::shared_ptr<raisin::ThreadPool> pool)
      : Node(pool)
  {
    subscriber_ = createSubscriber<raisin::std_msgs::msg::String>("my_topic", nullptr,
      [](const std::shared_ptr<raisin::std_msgs::msg::String> msg) {
      std::cout<<"Received message: " << msg->data << std::endl;
    });
  }

  ~SubscriberNode() {
    cleanupResources();
  }

 private:
  raisin::Subscriber<raisin::std_msgs::msg::String>::SharedPtr subscriber_;
};

int main() {
  raisinInit();
  std::vector<std::vector<std::string>> thread_spec = {{std::string("main")}};
  auto pool = std::make_shared<raisin::ThreadPool>(thread_spec, false);
  SubscriberNode node(pool);

  pool->getWorker(0)->run();

  return 0;
}
