// Copyright (c) 2024 Raion Robotics Inc.
//
// Any unauthorized copying, alteration, distribution, transmission,
// performance, display or use of this material is prohibited.
//
// All rights reserved.

#ifndef RAISIN_@@PROJECT_NAME@@_msg_@@MESSAGE_NAME@@_HPP_
#define RAISIN_@@PROJECT_NAME@@_msg_@@MESSAGE_NAME@@_HPP_

#include <vector>
#include <string>
#include <array>
#include <memory>
#include <cstdint>
#include "../../raisin_serialization_base.hpp"
@@INCLUDE_PATH@@

namespace raisin {
namespace @@PROJECT_NAME@@::msg {

class @@MESSAGE_NAME@@ {
public:

bool operator==(const @@MESSAGE_NAME@@& other) const {
  return true
    @@EQUAL_BUFFER_MEMBERS@@
  ;
}

inline void setBuffer(std::vector<unsigned char> &buffer) const {
  (void)getSize();
  @@SET_BUFFER_MEMBERS@@
}

inline unsigned char* setBuffer(unsigned char* buffer) const {
  (void)getSize();
  @@SET_BUFFER_MEMBERS2@@
  return buffer;
}

inline const unsigned char *getBuffer(const unsigned char *buffer) {
  const unsigned char* temp = buffer;
  @@GET_BUFFER_MEMBERS@@
  return temp;
}

inline const unsigned char *getBuffer(const std::vector<unsigned char>& buffer) {
  return getBuffer(buffer.data());
}

[[nodiscard]] inline uint32_t getSize() const {
  std::size_t temp = 0;
  @@BUFFER_SIZE_EXPRESSION@@
  return checkedSerializedLength(temp);
}

inline static std::string getDataType() {
  return "@@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@";
}

@@MEMBERS@@

using ConstSharedPtr = std::shared_ptr<const @@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@>;
using SharedPtr = std::shared_ptr<@@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@>;
using ConstUniquePtr = std::unique_ptr<const @@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@>;
using UniquePtr = std::unique_ptr<@@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@>;
};
}

static inline void setBuffer(std::vector<unsigned char>& buffer, const @@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@& msg) {
  msg.setBuffer(buffer);
}

static inline unsigned char* setBuffer(unsigned char* buffer, const @@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@& msg) {
  buffer = msg.setBuffer(buffer);
  return buffer;
}

static inline const unsigned char *getBuffer(const unsigned char *buffer, @@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@& msg) {
  return msg.getBuffer(buffer);
}

static inline const unsigned char *getBuffer(const std::vector<unsigned char>& buffer, @@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@& msg) {
return msg.getBuffer(buffer);
}

static inline void setBuffer(std::vector<unsigned char>& buffer, const std::vector<@@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@>& val) {
  std::size_t total_size = sizeof(uint32_t);
  for (const auto& item : val) {
    total_size = checkedSerializedSizeAdd(total_size, item.getSize(), 0);
  }
  (void)checkedSerializedLength(total_size);
  setBuffer(buffer, checkedSerializedLength(val.size()));
  for (size_t i = 0; i<val.size(); i++) {
    setBuffer(buffer, val[i]);
  }
}

template<size_t n>
static inline void setBuffer(std::vector<unsigned char>& buffer, const std::array<@@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@, n>& val) {
  for (size_t i = 0; i<n; i++) {
    setBuffer(buffer, val[i]);
  }
}

static inline unsigned char* setBuffer(unsigned char* buffer, const std::vector<@@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@>& val) {
  std::size_t total_size = sizeof(uint32_t);
  for (const auto& item : val) {
    total_size = checkedSerializedSizeAdd(total_size, item.getSize(), 0);
  }
  (void)checkedSerializedLength(total_size);
  buffer = setBuffer(buffer, checkedSerializedLength(val.size()));
  for (size_t i = 0; i<val.size(); i++) {
    buffer = setBuffer(buffer, val[i]);
  }

  return buffer;
}

template<size_t n>
static inline unsigned char* setBuffer(unsigned char* buffer, const std::array<@@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@, n>& val) {
  for (size_t i = 0; i<n; i++) {
    buffer = setBuffer(buffer, val[i]);
  }
  return buffer;
}

static inline const unsigned char *getBuffer(const unsigned char *buffer, std::vector<@@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@>& val) {
  uint32_t size;
  buffer = getBuffer(buffer, size);
  val.resize(size);
  for (size_t i=0; i<size; i++)
    buffer = getBuffer(buffer, val[i]);
  return buffer;
}

template<size_t n>
static inline const unsigned char *getBuffer(const unsigned char *buffer, std::array<@@PROJECT_NAME@@::msg::@@MESSAGE_NAME@@, n>& val) {
  for (size_t i=0; i<n; i++)
    buffer = getBuffer(buffer, val[i]);
  return buffer;
}

}


#endif //RAISIN_@@PROJECT_NAME@@_msg_@@MESSAGE_NAME@@_HPP_
