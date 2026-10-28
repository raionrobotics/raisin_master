// Copyright (c) 2024 Raion Robotics Inc.
//
// Any unauthorized copying, alteration, distribution, transmission,
// performance, display or use of this material is prohibited.
//
// All rights reserved.

#ifndef RAISIN_@@PROJECT_NAME@@_srv_@@SERVICE_NAME@@_HPP_
#define RAISIN_@@PROJECT_NAME@@_srv_@@SERVICE_NAME@@_HPP_

#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include "../../raisin_serialization_base.hpp"
@@INCLUDE_PATH@@


namespace raisin {
namespace @@PROJECT_NAME@@::srv {

class @@SERVICE_NAME@@ {
public:

inline static std::string getDataType() {
  return "@@PROJECT_NAME@@::srv::@@SERVICE_NAME@@";
}

class Request {
 public:
  bool operator==(const Request& other) const {
    return true
    @@REQUEST_EQUAL_BUFFER_MEMBERS@@
    ;
  }

  inline void setBuffer([[maybe_unused]] std::vector<unsigned char> &buffer) const {
    @@REQUEST_SET_BUFFER_MEMBERS@@
  };

  inline unsigned char* setBuffer(unsigned char* buffer) const {
    @@REQUEST_SET_BUFFER_MEMBERS2@@
    return buffer;
  }

  inline const unsigned char *getBuffer([[maybe_unused]] const unsigned char *buffer) {
    const unsigned char* temp = buffer;
    @@REQUEST_GET_BUFFER_MEMBERS@@;
    return temp;
  };

  inline const unsigned char *getBuffer([[maybe_unused]] const std::vector<unsigned char>& buffer) {
    return getBuffer(buffer.data());
  }

  [[nodiscard]] inline uint32_t getSize() const {
    std::size_t temp = 0;
    @@REQUEST_BUFFER_SIZE@@
    return checkedSerializedLength(temp);
  }

  inline static std::string getDataType() {
    return "@@PROJECT_NAME@@::srv::@@SERVICE_NAME@@::Request";
  }

  @@REQUEST_MEMBERS@@
  using ConstSharedPtr = std::shared_ptr<const @@PROJECT_NAME@@::srv::@@SERVICE_NAME@@::Request>;
  using SharedPtr = std::shared_ptr<@@PROJECT_NAME@@::srv::@@SERVICE_NAME@@::Request>;
};

class Response {
 public:
  bool operator==(const Response& other) const {
    return true
    @@RESPONSE_EQUAL_BUFFER_MEMBERS@@
    ;
  }

  inline void setBuffer([[maybe_unused]] std::vector<unsigned char> &buffer) const {
    @@RESPONSE_SET_BUFFER_MEMBERS@@
  };

  inline unsigned char* setBuffer(unsigned char* buffer) const {
    @@RESPONSE_SET_BUFFER_MEMBERS2@@
    return buffer;
  }

  inline const unsigned char *getBuffer([[maybe_unused]] const unsigned char *buffer) {
    const unsigned char* temp = buffer;
    @@RESPONSE_GET_BUFFER_MEMBERS@@
    return temp;
  };

  inline const unsigned char *getBuffer([[maybe_unused]] const std::vector<unsigned char>& buffer) {
    return getBuffer(buffer.data());
  }

  [[nodiscard]] inline uint32_t getSize() const {
    std::size_t temp = 0;
    @@RESPONSE_BUFFER_SIZE@@
    return checkedSerializedLength(temp);
  }

  inline static std::string getDataType() {
    return "@@PROJECT_NAME@@::srv::@@SERVICE_NAME@@::Response";
  }

  @@RESPONSE_MEMBERS@@
  using ConstSharedPtr = std::shared_ptr<const @@PROJECT_NAME@@::srv::@@SERVICE_NAME@@::Response>;
  using SharedPtr = std::shared_ptr<@@PROJECT_NAME@@::srv::@@SERVICE_NAME@@::Response>;
};

};
}

} // namespace raisin

#endif //RAISIN_@@PROJECT_NAME@@_srv_@@SERVICE_NAME@@_HPP_
