// Copyright (c) 2025 Raion Robotics Inc.
//
// Any unauthorized copying, alteration, distribution, transmission,
// performance, display or use of this material is prohibited.
//
// All rights reserved.
//

#include "raisin_empty_process_plugin/publisher_node.hpp"
#include <iostream>

using namespace raisin;

const char* shm_name = "my_shared_memory2";

int main() {
  raisinInit();
  std::vector<std::vector<std::string>> thread_spec = {{std::string("main")}};
  auto pool = std::make_shared<raisin::ThreadPool>(thread_spec, false);
  raisin::Node node(pool);
  empty_process::PublisherNode publisherNode(node, 10.0);

  pool->getWorker(0)->run(); // runs "main" worker and publish loop

  return 0;
}
