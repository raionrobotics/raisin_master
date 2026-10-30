import shutil
import subprocess
from pathlib import Path

import pytest

from commands import globals as raisin_globals
from commands import setup as raisin_setup

REPOSITORY = Path(__file__).parent
TEMPLATE = REPOSITORY / "templates" / "raisin_serialization_base.hpp"


@pytest.mark.skipif(shutil.which("g++") is None, reason="g++ is required")
def test_checked_lengths_preserve_wire_prefix_and_reject_overflow(
    tmp_path, monkeypatch
):
    source_project = tmp_path / "src" / "test_pkg"
    message_dir = source_project / "msg"
    service_dir = source_project / "srv"
    message_dir.mkdir(parents=True)
    service_dir.mkdir(parents=True)
    generated_root = tmp_path / "generated"
    install_root = tmp_path / "install"
    monkeypatch.setattr(raisin_globals, "script_directory", str(REPOSITORY))
    monkeypatch.setattr(raisin_globals, "generated_dir", str(generated_root))
    (message_dir / "Point.msg").write_text(
        "string text\nuint32 value\nuint32[] samples\n"
        "wstring wide\nwstring[] wide_samples\n",
        encoding="utf-8",
    )
    (service_dir / "Echo.srv").write_text(
        "string text\nuint32 value\n---\nstring text\n", encoding="utf-8"
    )
    raisin_setup.create_message_file(
        str(message_dir / "Point.msg"), str(source_project), str(install_root)
    )
    raisin_setup.create_service_file(
        str(service_dir / "Echo.srv"), str(source_project), str(install_root)
    )
    point_header = (
        generated_root / "include" / "test_pkg" / "msg" / "point.hpp"
    ).read_text(encoding="utf-8")
    echo_header = (
        generated_root / "include" / "test_pkg" / "srv" / "echo.hpp"
    ).read_text(encoding="utf-8")
    assert "checkedSerializedSizeAdd" in point_header
    assert "checkedSerializedByteLength" in point_header
    assert "sizeof(char16_t)" in point_header
    assert "temp +=" not in point_header
    assert "(void)getSize();" in point_header
    assert point_header.count(
        "checkedSerializedSizeAdd(total_size, item.getSize(), 0)"
    ) == 2
    assert "checkedSerializedSizeAdd" in echo_header
    assert "temp +=" not in echo_header
    assert echo_header.count("(void)getSize();") == 4
    raw_base = TEMPLATE.read_text(encoding="utf-8")
    assert "checkedSerializedValueSize(val)" in raw_base
    raw_vector_start = raw_base.index(
        "setBuffer(unsigned char* buffer, const std::vector<T>& val) {"
    )
    raw_vector_end = raw_base.index(
        "\n}\n\ntemplate <typename T>", raw_vector_start
    )
    raw_vector_setter = raw_base[raw_vector_start:raw_vector_end]
    assert (
        "checkedSerializedVectorByteLength(val.size(), sizeof(T))"
        in raw_vector_setter
    )
    assert raw_base.count(
        "checkedSerializedVectorByteLength(val.size(), sizeof(T))"
    ) == 2
    assert "val.size() * sizeof(T)" not in raw_vector_setter
    raw_bool_vector_setter_start = raw_base.index(
        "setBuffer(unsigned char* buffer,\n                             const std::vector<bool>& val) {"
    )
    raw_bool_vector_end = raw_base.index("\n}\n", raw_bool_vector_setter_start)
    raw_bool_vector_setter = raw_base[
        raw_bool_vector_setter_start:raw_bool_vector_end
    ]
    assert (
        "checkedSerializedVectorByteLength(val.size(), sizeof(bool))"
        in raw_bool_vector_setter
    )
    assert raw_base.count(
        "checkedSerializedVectorByteLength(val.size(), sizeof(bool))"
    ) == 2
    generated_base = generated_root / "include" / "raisin_serialization_base.hpp"
    generated_base.parent.mkdir(parents=True, exist_ok=True)
    generated_base.write_text(
        TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8"
    )

    source = tmp_path / "serialization_lengths.cpp"
    source.write_text(
r'''#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#include "raisin_serialization_base.hpp"
#include "test_pkg/msg/point.hpp"
#include "test_pkg/srv/echo.hpp"

int main() {
  const auto max = static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max());
  struct OversizeElement {
    std::string marker;
    std::uint32_t getSize() const {
      return std::numeric_limits<std::uint32_t>::max();
    }
  };
  bool nested_sequence_overflow_rejected = false;
  try {
    (void)raisin::checkedSerializedValueSize(
        std::vector<OversizeElement>{OversizeElement{}});
  } catch (const std::length_error&) {
    nested_sequence_overflow_rejected = true;
  }
  if (!nested_sequence_overflow_rejected) return 34;
  if (raisin::checkedSerializedLength(max) != std::numeric_limits<std::uint32_t>::max()) return 1;
  if (raisin::checkedSerializedByteLength(max / 2, 2) != max - 1) return 2;
  const auto largest_vector_count =
      (max - sizeof(std::uint32_t)) / sizeof(std::uint32_t);
  const auto largest_vector_bytes = largest_vector_count * sizeof(std::uint32_t);
  if (raisin::checkedSerializedVectorByteLength(
          largest_vector_count, sizeof(std::uint32_t)) != largest_vector_bytes)
    return 30;
  bool vector_aggregate_overflow_rejected = false;
  try {
    (void)raisin::checkedSerializedVectorByteLength(
        largest_vector_count + 1, sizeof(std::uint32_t));
  } catch (const std::length_error&) {
    vector_aggregate_overflow_rejected = true;
  }
  if (!vector_aggregate_overflow_rejected) return 31;
  const auto largest_bool_count =
      (max - sizeof(std::uint32_t)) / sizeof(bool);
  if (raisin::checkedSerializedVectorByteLength(
          largest_bool_count, sizeof(bool)) != largest_bool_count * sizeof(bool))
    return 32;
  vector_aggregate_overflow_rejected = false;
  try {
    (void)raisin::checkedSerializedVectorByteLength(
        largest_bool_count + 1, sizeof(bool));
  } catch (const std::length_error&) {
    vector_aggregate_overflow_rejected = true;
  }
  if (!vector_aggregate_overflow_rejected) return 33;
  constexpr std::size_t overhead = sizeof(std::int64_t) + sizeof(std::uint32_t);
  if (raisin::checkedSerializedLengthWithOverhead(max - overhead, overhead) != max) return 3;
  if (raisin::checkedBufferSize(max - 2, 2, max) != max) return 4;
  const std::vector<unsigned char> empty_buffer;
  bool wire_buffer_limit_rejected = false;
  try {
    (void)raisin::checkedBufferSize(max, 1, empty_buffer.max_size());
  } catch (const std::length_error&) {
    wire_buffer_limit_rejected = true;
  }
  if (!wire_buffer_limit_rejected) return 29;
  bool buffer_growth_rejected = false;
  try {
    (void)raisin::checkedBufferSize(max - 1, 2, max);
  } catch (const std::length_error&) {
    buffer_growth_rejected = true;
  }
  if (!buffer_growth_rejected) return 5;
  buffer_growth_rejected = false;
  try {
    (void)raisin::checkedBufferSize(max, 1, max - 1);
  } catch (const std::length_error&) {
    buffer_growth_rejected = true;
  }
  if (!buffer_growth_rejected) return 6;
  if (raisin::checkedSerializedSizeAdd(max - 1, 1, 0) != max) return 25;
  bool aggregate_size_rejected = false;
  try {
    (void)raisin::checkedSerializedSizeAdd(max - 1, 2, 0);
  } catch (const std::length_error&) {
    aggregate_size_rejected = true;
  }
  if (!aggregate_size_rejected) return 26;
  aggregate_size_rejected = false;
  try {
    (void)raisin::checkedSerializedSizeAdd(max, 0, sizeof(std::uint32_t));
  } catch (const std::length_error&) {
    aggregate_size_rejected = true;
  }
  if (!aggregate_size_rejected) return 27;
  aggregate_size_rejected = false;
  try {
    (void)raisin::checkedSerializedSizeAdd(max, max, 0);
  } catch (const std::length_error&) {
    aggregate_size_rejected = true;
  }
  if (!aggregate_size_rejected) return 28;
  bool rejected = false;
  if (max < std::numeric_limits<std::size_t>::max()) {
    try {
      (void)raisin::checkedSerializedLength(max + 1);
    } catch (const std::length_error&) {
      rejected = true;
    }
    if (!rejected) return 7;
  }
  rejected = false;
  try {
    (void)raisin::checkedSerializedByteLength(max / 2 + 1, 2);
  } catch (const std::length_error&) {
    rejected = true;
  }
  if (!rejected) return 8;
  rejected = false;
  try {
    (void)raisin::checkedSerializedLengthWithOverhead(max - overhead + 1, overhead);
  } catch (const std::length_error&) {
    rejected = true;
  }
  if (!rejected) return 9;

  std::vector<unsigned char> bytes;
  raisin::setBuffer(bytes, std::string("abc"));
  std::vector<unsigned char> expected_string(sizeof(std::uint32_t) + 3);
  const std::uint32_t legacy_string_size = 3;
  std::memcpy(expected_string.data(), &legacy_string_size, sizeof(legacy_string_size));
  std::memcpy(expected_string.data() + sizeof(legacy_string_size), "abc", 3);
  if (bytes != expected_string) return 10;
  std::uint32_t string_size = 0;
  const unsigned char* cursor = raisin::getBuffer(bytes.data(), string_size);
  if (string_size != 3 || std::string(reinterpret_cast<const char*>(cursor), string_size) != "abc") return 11;

  unsigned char raw_string[sizeof(std::uint32_t) + 3]{};
  unsigned char* raw_end = raisin::setBuffer(raw_string, std::string("abc"));
  if (raw_end - raw_string != sizeof(raw_string)) return 12;
  std::string raw_round_trip;
  (void)raisin::getBuffer(raw_string, raw_round_trip);
  if (raw_round_trip != "abc") return 13;

  bytes.clear();
  const std::u16string u16_value = u"xy";
  raisin::setBuffer(bytes, u16_value);
  std::u16string u16_round_trip;
  (void)raisin::getBuffer(bytes.data(), u16_round_trip);
  if (u16_round_trip != u16_value) return 14;

  bytes.clear();
  const std::wstring wide_value = L"xy";
  raisin::setBuffer(bytes, wide_value);
  std::wstring wide_round_trip;
  (void)raisin::getBuffer(bytes.data(), wide_round_trip);
  if (wide_round_trip != wide_value) return 15;

  bytes.clear();
  raisin::setBuffer(bytes, std::vector<std::uint16_t>{7, 9});
  std::vector<unsigned char> expected_vector(sizeof(std::uint32_t) + 2 * sizeof(std::uint16_t));
  const std::uint32_t legacy_vector_count = 2;
  const std::uint16_t legacy_vector_values[] = {7, 9};
  std::memcpy(expected_vector.data(), &legacy_vector_count, sizeof(legacy_vector_count));
  std::memcpy(expected_vector.data() + sizeof(legacy_vector_count), legacy_vector_values, sizeof(legacy_vector_values));
  if (bytes != expected_vector) return 16;
  std::uint32_t vector_count = 0;
  (void)raisin::getBuffer(bytes.data(), vector_count);
  if (vector_count != 2) return 17;

  bytes.clear();
  const std::vector<std::string> strings{"a", "bc"};
  const auto strings_size = raisin::checkedSerializedValueSize(strings);
  if (!strings_size.has_value() || *strings_size !=
      sizeof(std::uint32_t) * 3 + strings[0].size() + strings[1].size())
    return 35;
  raisin::setBuffer(bytes, strings);
  std::vector<std::string> strings_round_trip;
  (void)raisin::getBuffer(bytes.data(), strings_round_trip);
  if (strings_round_trip != strings) return 18;

  bytes.clear();
  const std::vector<raisin::MessageInformation> information{
      raisin::MessageInformation{123, "mission", "fms/test", 7}};
  const auto information_size =
      raisin::checkedSerializedValueSize(information.front());
  if (!information_size.has_value() ||
      *information_size != sizeof(std::int64_t) + sizeof(std::uint32_t) + 7 +
                               sizeof(std::uint32_t) + 8 + sizeof(std::int32_t))
    return 39;
  raisin::setBuffer(bytes, information);
  std::vector<raisin::MessageInformation> information_round_trip;
  (void)raisin::getBuffer(bytes.data(), information_round_trip);
  if (information_round_trip.size() != 1 ||
      information_round_trip[0].timestamp != 123 ||
      information_round_trip[0].title != "mission" ||
      information_round_trip[0].dataType != "fms/test" ||
      information_round_trip[0].id != 7)
    return 36;

  bytes.clear();
  raisin::SerializedMessage serialized_message;
  serialized_message.title = "m";
  serialized_message.id = 8;
  serialized_message.msg = {1, 2};
  const auto serialized_message_size =
      raisin::checkedSerializedValueSize(serialized_message);
  if (!serialized_message_size.has_value() ||
      *serialized_message_size != sizeof(std::uint32_t) + 1 +
                                     sizeof(std::int32_t) +
                                     sizeof(std::uint32_t) + 2)
    return 37;
  const std::vector<raisin::SerializedMessage> serialized_messages{
      serialized_message};
  raisin::setBuffer(bytes, serialized_messages);
  std::vector<raisin::SerializedMessage> serialized_messages_round_trip(1);
  (void)raisin::getBuffer(bytes.data(), serialized_messages_round_trip);
  if (serialized_messages_round_trip.size() != 1 ||
      serialized_messages_round_trip[0].title != "m" ||
      serialized_messages_round_trip[0].id != 8 ||
      serialized_messages_round_trip[0].msg !=
          std::vector<unsigned char>({1, 2}))
    return 38;

  bytes.clear();
  const std::vector<bool> flags{true, false};
  raisin::setBuffer(bytes, flags);
  std::vector<bool> flags_round_trip;
  (void)raisin::getBuffer(bytes.data(), flags_round_trip);
  if (flags_round_trip != flags) return 19;

  bytes.clear();
  raisin::test_pkg::msg::Point point;
  point.text = "x";
  point.value = 42;
  point.samples = {7, 9};
  point.wide = u"xy";
  point.wide_samples = {u"z"};
  raisin::setBuffer(bytes, std::vector<raisin::test_pkg::msg::Point>{point});
  std::uint32_t message_count = 0;
  (void)raisin::getBuffer(bytes.data(), message_count);
  if (message_count != 1) return 20;
  if (point.getSize() != sizeof(std::uint32_t) + 1 + sizeof(point.value) +
                             sizeof(std::uint32_t) + 2 * sizeof(std::uint32_t) +
                             sizeof(std::uint32_t) + 2 * sizeof(char16_t) +
                             sizeof(std::uint32_t) + sizeof(std::uint32_t) +
                             sizeof(char16_t)) return 21;

  raisin::test_pkg::srv::Echo::Request request;
  request.text = "x";
  request.value = 42;
  if (request.getSize() != sizeof(std::uint32_t) + 1 + sizeof(request.value)) return 22;
  raisin::test_pkg::srv::Echo::Response response;
  response.text = "xy";
  if (response.getSize() != sizeof(std::uint32_t) + 2) return 23;

  raisin::SerializedMessage message;
  message.msg.resize(2);
  if (message.size() != sizeof(std::int64_t) + sizeof(std::uint32_t) + 2) return 24;
  return 0;
}
''',
        encoding="utf-8",
    )
    binary = tmp_path / "serialization_lengths"
    subprocess.run(
        [
            "g++",
            "-std=c++17",
            "-Wconversion",
            "-Werror",
            "-I",
            str(generated_root / "include"),
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run([str(binary)], check=True)
