// Copyright (c) 2025 Raion Robotics Inc.
//
// Any unauthorized copying, alteration, distribution, transmission,
// performance, display or use of this material is prohibited.
//
// All rights reserved.

#include "raisin_empty_process_plugin/empty_process_plugin.hpp"
#include "raisin_empty_process_plugin/publisher_node.hpp"

namespace raisin
{

namespace plugin
{

empty_processPlugin::empty_processPlugin(
  raisim::World & world, raisim::RaisimServer & server,
  raisim::World & worldSim, raisim::RaisimServer & serverSim, GlobalResource & globalResource)
: Plugin(world, server, worldSim, serverSim, globalResource),
  Node("raisin_empty_process_plugin", globalResource.paramRoot, globalResource.network)
{
  pluginType_ = PluginType::CUSTOM;

  if (param_) {
    runSeparateProcess_ = static_cast<bool>((*param_)("run_separate_process", true));
    publishRateHz_ = static_cast<double>((*param_)("publish_rate_hz", 10.0));
  }
}

empty_processPlugin::~empty_processPlugin()
{
  cleanupResources();
}

bool empty_processPlugin::init()
{
  if (!runSeparateProcess_) {
    inlinePublisher_ =
      std::make_unique<empty_process::PublisherNode>(*this, publishRateHz_);
  } else {
    process_ = std::make_unique<Process>(
      "raisin_empty_process_plugin", "raisin_empty_process_plugin_process");
  }

  return true;
}

bool empty_processPlugin::advance()
{
  return true;
}

bool empty_processPlugin::reset()
{
  return true;
}

bool empty_processPlugin::shouldTerminate()
{
  if (runSeparateProcess_ && process_) {
    return !process_->isAlive();
  }

  return false;
}


extern "C" Plugin * create(
  raisim::World & world, raisim::RaisimServer & server,
  raisim::World & worldSim, raisim::RaisimServer & serverSim, GlobalResource & globalResource)
{
  return new empty_processPlugin(world, server, worldSim, serverSim, globalResource);
}

extern "C" void destroy(empty_processPlugin * p)
{
  delete p;
}

} // namespace plugin

} // namespace raisin
