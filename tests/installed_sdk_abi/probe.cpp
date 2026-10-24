#include "raisin_tf/transform.hpp"
#include "raisin_network/raisin.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

static_assert(EIGEN_MAX_ALIGN_BYTES == PROBE_EXPECTED_EIGEN_MAX_ALIGN_BYTES);
static_assert(alignof(Eigen::Isometry3d) == PROBE_EXPECTED_ISOMETRY3D_ALIGN_BYTES);

// Both layouts are valid C++ objects under the consumer's actual Eigen ABI.
// With 16-byte alignment, value is deliberately at offset 16 mod 32; with
// 32-byte alignment, the compiler inserts padding and value is 0 mod 32.
struct alignas(32) PoseFixture {
    std::array<char, 16> prefix;
    Eigen::Isometry3d value;
};

int main() {
    raisin::raisinInit();
    auto network = std::make_shared<raisin::Network>(
            "sdk-abi-proof", "pc",
            std::vector<std::vector<std::string>>{{"main"}},
            std::vector<std::string>{"lo"}, "", 60, false);
    {
        raisin::tf::Transform transform(network);
        PoseFixture sample{};
        sample.value = Eigen::Isometry3d::Identity();
        sample.value.translation() = Eigen::Vector3d(2, 2, 0);

        const auto pose_mod32 = reinterpret_cast<std::uintptr_t>(&sample.value) % 32;
        if (pose_mod32 % alignof(Eigen::Isometry3d) != 0) {
            std::cerr << "fixture is not aligned for the consumer Eigen ABI\n";
            return 2;
        }
        std::cout << "{\"stage\":\"before_set\",\"eigen_alignment\":"
                  << alignof(Eigen::Isometry3d)
                  << ",\"eigen_max_align\":" << EIGEN_MAX_ALIGN_BYTES
                  << ",\"pose_mod32\":" << pose_mod32 << "}" << std::endl;

        transform.setTransform("map", "base", sample.value);
        if (!transform.canTransform("map", "base")
                || !transform.getTransform("map", "base").isApprox(sample.value, 1e-12)) {
            return 3;
        }
        transform.sendTransform("map", "base", sample.value);
        if (!transform.getTransform("map", "base").isApprox(sample.value, 1e-12)) {
            return 4;
        }
        std::cout << "{\"stage\":\"actual_tf_roundtrip_passed\"}" << std::endl;
    }
    network->shutdown();
    return 0;
}
