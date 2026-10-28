// Copyright (c) 2024 Raion Robotics Inc.
//
// Any unauthorized copying, alteration, distribution, transmission,
// performance, display or use of this material is prohibited.
//
// All rights reserved.

#ifndef RAISIN_WS_SERIALIZATION_BASE_HPP_
#define RAISIN_WS_SERIALIZATION_BASE_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace raisin {

static inline uint32_t checkedSerializedLength(std::size_t length) {
  if (length > std::numeric_limits<uint32_t>::max()) {
    throw std::length_error("serialized length exceeds the 32-bit wire limit");
  }
  return static_cast<uint32_t>(length);
}

static inline uint32_t checkedSerializedByteLength(std::size_t count,
                                                   std::size_t element_size) {
  if (element_size != 0 &&
      count > std::numeric_limits<uint32_t>::max() / element_size) {
    throw std::length_error("serialized byte length exceeds the 32-bit wire limit");
  }
  return checkedSerializedLength(count * element_size);
}

static inline uint32_t checkedSerializedLengthWithOverhead(
    std::size_t payload_length, std::size_t overhead) {
  const auto maximum = static_cast<std::size_t>(
      std::numeric_limits<uint32_t>::max());
  if (overhead > maximum || payload_length > maximum - overhead) {
    throw std::length_error("serialized size exceeds the 32-bit wire limit");
  }
  return static_cast<uint32_t>(payload_length + overhead);
}

static inline std::size_t checkedSerializedSizeAdd(std::size_t current_size,
                                                  std::size_t payload_size,
                                                  std::size_t overhead) {
  const auto maximum = static_cast<std::size_t>(
      std::numeric_limits<uint32_t>::max());
  if (current_size > maximum || overhead > maximum - current_size ||
      payload_size > maximum - current_size - overhead) {
    throw std::length_error("serialized size exceeds the 32-bit wire limit");
  }
  return current_size + overhead + payload_size;
}

static inline std::size_t checkedBufferSize(std::size_t current_size,
                                           std::size_t additional_size,
                                           std::size_t maximum_size) {
  if (current_size > maximum_size ||
      additional_size > maximum_size - current_size) {
    throw std::length_error("serialized buffer size overflow");
  }
  return current_size + additional_size;
}

static inline void growBuffer(std::vector<unsigned char>& buffer,
                              std::size_t additional_size) {
  buffer.resize(checkedBufferSize(buffer.size(), additional_size,
                                  buffer.max_size()));
}

//////////////////////////////////////
/// getBuffer vector methods

template<typename T>
static inline std::enable_if_t<std::is_trivially_copyable_v<T>, void>
setBuffer(std::vector<unsigned char>& buffer, const T& val) {
  const auto originalSize = buffer.size();
  growBuffer(buffer, sizeof(T));
  std::memcpy(buffer.data() + originalSize, &val, sizeof(T));
}

static inline void setBuffer(std::vector<unsigned char>& buffer, const std::string& val) {
  const uint32_t size = checkedSerializedLength(val.size());
  setBuffer(buffer, size);
  buffer.insert(buffer.end(), val.begin(), val.end());
}

static inline void setBuffer(std::vector<unsigned char>& buffer, const std::u16string& val) {
  const uint32_t size = checkedSerializedByteLength(val.size(), sizeof(char16_t));
  setBuffer(buffer, size);
  auto originalSize = buffer.size();
  growBuffer(buffer, size);
  std::memcpy(buffer.data() + originalSize, val.data(), size);
}

static inline void setBuffer(std::vector<unsigned char>& buffer, const std::wstring& val) {
  const uint32_t size = checkedSerializedByteLength(val.size(), sizeof(wchar_t));
  setBuffer(buffer, size);
  auto originalSize = buffer.size();
  growBuffer(buffer, size);
  std::memcpy(buffer.data() + originalSize, val.data(), size);
}

template<typename T>
static inline std::enable_if_t<
  std::is_trivially_copyable<T>::value && !std::is_same_v<T, bool>, void>
setBuffer(std::vector<unsigned char>& buffer, const std::vector<T>& val) {
  const uint32_t size = checkedSerializedLength(val.size());
  setBuffer(buffer, size);
  const auto originalSize = buffer.size();
  const auto bytes = checkedSerializedByteLength(size, sizeof(T));
  growBuffer(buffer, bytes);
  if (!val.empty()) {
    std::memcpy(buffer.data() + originalSize, val.data(), bytes);
  }
}

template<typename T>
static inline std::enable_if_t<
  !std::is_trivially_copyable<T>::value || std::is_same_v<T, bool>, void>
setBuffer(std::vector<unsigned char>& buffer, const std::vector<T>& val) {
  setBuffer(buffer, checkedSerializedLength(val.size()));
  for (size_t i = 0; i<val.size(); i++) {
    setBuffer(buffer, val[i]);
  }
}

template<typename T, size_t N>
static inline std::enable_if_t<std::is_trivially_copyable_v<T>, void>
setBuffer(std::vector<unsigned char>& buffer, const std::array<T, N>& val) {
  const auto originalSize = buffer.size();
  growBuffer(buffer, sizeof(T) * N);
  if (N > 0) {
    std::memcpy(buffer.data() + originalSize, val.data(), sizeof(T) * N);
  }
}

template<typename T, size_t N>
static inline std::enable_if_t<!std::is_trivially_copyable_v<T>, void>
setBuffer(std::vector<unsigned char>& buffer, const std::array<T, N>& val) {
  for (const auto& element : val) {
    setBuffer(buffer, element);
  }
}

static inline void setBuffer(std::vector<unsigned char>& buffer, const std::vector<bool>& val) {
  setBuffer(buffer, checkedSerializedLength(val.size()));
  auto originalSize = buffer.size();
  growBuffer(buffer, checkedSerializedByteLength(val.size(), sizeof(bool)));
  for (size_t i = 0; i<val.size(); i++) {
    bool temp = val[i];
    std::memcpy(buffer.data() + originalSize + i, &temp, sizeof(bool));
  }
}

template <typename T, typename... Args>
static inline std::enable_if_t<(sizeof...(Args) > 0), void>
setBuffer(std::vector<unsigned char>& buffer, const T& val,
          const Args&... rest) {
  setBuffer(buffer, val);      // Process the current argument
  setBuffer(buffer, rest...);  // Recursively process the remaining arguments
}

//////////////////////////////////////
/// getBuffer Char methods

template<typename T>
static std::enable_if_t<std::is_trivially_copyable_v<T>, unsigned char*>
    setBuffer(unsigned char* buffer, const T& val) {
  std::memcpy(buffer, &val, sizeof(T));
  return buffer + sizeof(T);
}

static unsigned char* setBuffer(unsigned char* buffer,
                             const std::string& val) {
  const uint32_t size = checkedSerializedLength(val.size());
  buffer = setBuffer(buffer, size);
  std::memcpy(buffer, val.data(), size);
  return buffer + size;
}

static unsigned char* setBuffer(unsigned char* buffer,
                             const std::u16string& val) {
  const uint32_t size = checkedSerializedByteLength(val.size(), sizeof(char16_t));
  buffer = setBuffer(buffer, size);
  std::memcpy(buffer, val.data(), size);
  return buffer + size;
}

static unsigned char* setBuffer(unsigned char* buffer,
                             const std::wstring& val) {
  const uint32_t size = checkedSerializedByteLength(val.size(), sizeof(wchar_t));
  buffer = setBuffer(buffer, size);
  std::memcpy(buffer, val.data(), size);
  return buffer + size;
}

template <typename T>
static std::enable_if_t<
  std::is_trivially_copyable_v<T> && !std::is_same_v<T, bool>, unsigned char*>
setBuffer(unsigned char* buffer, const std::vector<T>& val) {
  buffer = setBuffer(buffer, checkedSerializedLength(val.size()));
  const size_t bytes = val.size() * sizeof(T);
  if (bytes > 0) {
    std::memcpy(buffer, val.data(), bytes);
    buffer += bytes;
  }
  return buffer;
}

template <typename T>
static std::enable_if_t<
  !std::is_trivially_copyable_v<T> || std::is_same_v<T, bool>, unsigned char*>
setBuffer(unsigned char* buffer, const std::vector<T>& val) {
  buffer = setBuffer(buffer, checkedSerializedLength(val.size()));
  for (size_t i = 0; i < val.size(); i++) {
    buffer = setBuffer(buffer, val[i]);
  }
  return buffer;
}

template <typename T, size_t N>
static std::enable_if_t<std::is_trivially_copyable_v<T>, unsigned char*>
setBuffer(unsigned char* buffer, const std::array<T, N>& val) {
  if (N > 0) {
    std::memcpy(buffer, val.data(), sizeof(T) * N);
    buffer += sizeof(T) * N;
  }
  return buffer;
}

template <typename T, size_t N>
static std::enable_if_t<!std::is_trivially_copyable_v<T>, unsigned char*>
setBuffer(unsigned char* buffer, const std::array<T, N>& val) {
  for (const auto& element : val) {
    buffer = setBuffer(buffer, element);
  }
  return buffer;
}

static unsigned char* setBuffer(unsigned char* buffer,
                             const std::vector<bool>& val) {
  buffer = setBuffer(buffer, checkedSerializedLength(val.size()));
  for (size_t i = 0; i < val.size(); i++) {
    bool temp = val[i];
    buffer = setBuffer(buffer, temp);
  }
  return buffer;
}


template <typename T>
static inline typename std::enable_if<std::is_trivially_copyable_v<T>,
                                      const unsigned char*>::type
getBuffer(const unsigned char* buffer, T& val) {
  std::memcpy(&val, buffer, sizeof(T));
  return buffer + sizeof(T);
}

static inline const unsigned char* getBuffer(const unsigned char* buffer,
                                             std::string& val) {
  uint32_t size;
  buffer = getBuffer(buffer, size);
  val.resize(size);
  std::memcpy(val.data(), buffer, size);
  return buffer + size;
}

static inline const unsigned char* getBuffer(const unsigned char* buffer,
                                             std::u16string& val) {
  uint32_t sizeInBytes;
  buffer = getBuffer(buffer, sizeInBytes);
  std::size_t count = sizeInBytes / sizeof(char16_t);
  val.resize(count);
  const std::size_t bytesToCopy = count * sizeof(char16_t);
  if (bytesToCopy > 0) {
    std::memcpy(val.data(), buffer, bytesToCopy);
  }
  return buffer + sizeInBytes;
}

static inline const unsigned char* getBuffer(const unsigned char* buffer,
                                             std::wstring& val) {
  uint32_t sizeInBytes;
  buffer = getBuffer(buffer, sizeInBytes);
  std::size_t count = sizeInBytes / sizeof(wchar_t);
  val.resize(count);
  const std::size_t bytesToCopy = count * sizeof(wchar_t);
  if (bytesToCopy > 0) {
    std::memcpy(val.data(), buffer, bytesToCopy);
  }
  return buffer + sizeInBytes;
}

template <typename T>
static inline const unsigned char* getBuffer(const unsigned char* buffer,
                                             std::vector<T>& val) {
  uint32_t size;
  buffer = getBuffer(buffer, size);
  val.resize(size);
  if constexpr (std::is_trivially_copyable_v<T> && !std::is_same_v<T, bool>) {
    const size_t bytes = static_cast<size_t>(size) * sizeof(T);
    if (bytes > 0) {
      std::memcpy(val.data(), buffer, bytes);
      buffer += bytes;
    }
    return buffer;
  } else {
    for (size_t i = 0; i < size; i++) buffer = getBuffer(buffer, val[i]);
    return buffer;
  }
}

static inline const unsigned char* getBuffer(const unsigned char* buffer,
                                             std::vector<bool>& val) {
  uint32_t size;
  buffer = getBuffer(buffer, size);
  val.resize(size);
  for (size_t i = 0; i<val.size(); i++) {
    bool temp;
    std::memcpy(&temp, buffer + i * sizeof(bool), sizeof(bool));
    val[i] = temp;
  }
  return buffer + size * sizeof(bool);
}

template <typename T, size_t N>
static inline const unsigned char* getBuffer(const unsigned char* buffer, std::array<T, N>& val) {
  if constexpr (std::is_trivially_copyable_v<T>) {
    if (N > 0) {
      std::memcpy(val.data(), buffer, sizeof(T) * N);
      buffer += sizeof(T) * N;
    }
    return buffer;
  } else {
    for (auto& element : val) {
      buffer = getBuffer(buffer, element);
    }
    return buffer;
  }
}

template<typename T, typename... Args>
static inline typename std::enable_if<(sizeof...(Args) > 0), const unsigned char*>::type
getBuffer(const unsigned char* buffer, T& val, Args&... rest) {
  return getBuffer(getBuffer(buffer, val), rest...);
}

struct MessageInformation {
  int64_t timestamp;
  std::string title;
  std::string dataType;
  int32_t id;
};

static inline void setBuffer(std::vector<unsigned char>& buffer, const MessageInformation& val) {
  setBuffer(buffer, val.timestamp);
  setBuffer(buffer, val.title);
  setBuffer(buffer, val.dataType);
  setBuffer(buffer, val.id);
}

static inline const unsigned char *getBuffer(const unsigned char* buffer, MessageInformation& val) {
  const unsigned char* tempBuffer = getBuffer(buffer, val.timestamp);
  tempBuffer = getBuffer(tempBuffer, val.title);
  tempBuffer = getBuffer(tempBuffer, val.dataType);
  tempBuffer = getBuffer(tempBuffer, val.id);
  return tempBuffer;
}

struct SerializedMessage
{
  SerializedMessage() {}

  uint32_t size()
  {
    return checkedSerializedLengthWithOverhead(
        msg.size(), sizeof(int64_t) + sizeof(uint32_t));
  }

  std::string title, dataType;
  int64_t timestamp;
  std::vector<unsigned char> msg;
  int32_t id;
};

static inline void setBuffer(std::vector<unsigned char> & buffer, const SerializedMessage & val)
{
  setBuffer(buffer, val.title, val.id, val.msg);
}

static inline const unsigned char * getBuffer(const unsigned char * buffer, SerializedMessage & val)
{
  return getBuffer(buffer, val.title, val.id, val.msg);
}

}

#endif // RAISIN_WS_SERIALIZATION_BASE_HPP_
