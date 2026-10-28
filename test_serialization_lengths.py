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
        "string text\nuint32 value\n", encoding="utf-8"
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
  if (raisin::checkedSerializedLength(max) != std::numeric_limits<std::uint32_t>::max()) return 1;
  if (raisin::checkedSerializedByteLength(max / 2, 2) != max - 1) return 2;
  constexpr std::size_t overhead = sizeof(std::int64_t) + sizeof(std::uint32_t);
  if (raisin::checkedSerializedLengthWithOverhead(max - overhead, overhead) != max) return 3;
  if (raisin::checkedBufferSize(max - 2, 2, max) != max) return 4;
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
  if (bytes != expected_string) return 7;
  std::uint32_t string_size = 0;
  const unsigned char* cursor = raisin::getBuffer(bytes.data(), string_size);
  if (string_size != 3 || std::string(reinterpret_cast<const char*>(cursor), string_size) != "abc") return 8;

  unsigned char raw_string[sizeof(std::uint32_t) + 3]{};
  unsigned char* raw_end = raisin::setBuffer(raw_string, std::string("abc"));
  if (raw_end - raw_string != sizeof(raw_string)) return 9;
  std::string raw_round_trip;
  (void)raisin::getBuffer(raw_string, raw_round_trip);
  if (raw_round_trip != "abc") return 10;

  bytes.clear();
  const std::u16string u16_value = u"xy";
  raisin::setBuffer(bytes, u16_value);
  std::u16string u16_round_trip;
  (void)raisin::getBuffer(bytes.data(), u16_round_trip);
  if (u16_round_trip != u16_value) return 11;

  bytes.clear();
  const std::wstring wide_value = L"xy";
  raisin::setBuffer(bytes, wide_value);
  std::wstring wide_round_trip;
  (void)raisin::getBuffer(bytes.data(), wide_round_trip);
  if (wide_round_trip != wide_value) return 12;

  bytes.clear();
  raisin::setBuffer(bytes, std::vector<std::uint16_t>{7, 9});
  std::vector<unsigned char> expected_vector(sizeof(std::uint32_t) + 2 * sizeof(std::uint16_t));
  const std::uint32_t legacy_vector_count = 2;
  const std::uint16_t legacy_vector_values[] = {7, 9};
  std::memcpy(expected_vector.data(), &legacy_vector_count, sizeof(legacy_vector_count));
  std::memcpy(expected_vector.data() + sizeof(legacy_vector_count), legacy_vector_values, sizeof(legacy_vector_values));
  if (bytes != expected_vector) return 13;
  std::uint32_t vector_count = 0;
  (void)raisin::getBuffer(bytes.data(), vector_count);
  if (vector_count != 2) return 14;

  bytes.clear();
  const std::vector<std::string> strings{"a", "bc"};
  raisin::setBuffer(bytes, strings);
  std::vector<std::string> strings_round_trip;
  (void)raisin::getBuffer(bytes.data(), strings_round_trip);
  if (strings_round_trip != strings) return 15;

  bytes.clear();
  const std::vector<bool> flags{true, false};
  raisin::setBuffer(bytes, flags);
  std::vector<bool> flags_round_trip;
  (void)raisin::getBuffer(bytes.data(), flags_round_trip);
  if (flags_round_trip != flags) return 16;

  bytes.clear();
  raisin::test_pkg::msg::Point point;
  point.text = "x";
  point.value = 42;
  raisin::setBuffer(bytes, std::vector<raisin::test_pkg::msg::Point>{point});
  std::uint32_t message_count = 0;
  (void)raisin::getBuffer(bytes.data(), message_count);
  if (message_count != 1) return 17;
  if (point.getSize() != sizeof(std::uint32_t) + 1 + sizeof(point.value)) return 18;

  raisin::test_pkg::srv::Echo::Request request;
  request.text = "x";
  request.value = 42;
  if (request.getSize() != sizeof(std::uint32_t) + 1 + sizeof(request.value)) return 19;
  raisin::test_pkg::srv::Echo::Response response;
  response.text = "xy";
  if (response.getSize() != sizeof(std::uint32_t) + 2) return 20;

  raisin::SerializedMessage message;
  message.msg.resize(2);
  if (message.size() != sizeof(std::int64_t) + sizeof(std::uint32_t) + 2) return 21;
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
