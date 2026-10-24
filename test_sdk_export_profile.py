"""Installed CMake consumers must inherit the SDK's selected CPU profile."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent
HELPER = REPO / "cmake" / "raisin_helper.cmake"


@unittest.skipUnless(
    shutil.which("cmake") is not None,
    "CMake is required for installed SDK export tests",
)
class TestInstalledSdkCpuProfile(unittest.TestCase):
    def configure_and_install(
        self, root: Path, march: str, uses_eigen: bool = True
    ) -> Path:
        producer = root / "producer"
        producer.mkdir()
        (producer / "include").mkdir()
        (producer / "source.cpp").write_text("int sdk_symbol() { return 0; }\n")
        eigen_config = root / "eigen-package" / "Eigen3Config.cmake"
        eigen_config.parent.mkdir()
        eigen_include = root / "eigen-package" / "include" / "Eigen"
        eigen_include.mkdir(parents=True)
        (eigen_include / "Core").write_text("#define EIGEN_MAX_ALIGN_BYTES 32\n")
        eigen_config.write_text(
            "if(NOT TARGET Eigen3::Eigen)\n"
            "  add_library(Eigen3::Eigen INTERFACE IMPORTED)\n"
            "endif()\n"
            'set_target_properties(Eigen3::Eigen PROPERTIES '
            f'INTERFACE_INCLUDE_DIRECTORIES "{eigen_include.parent}")\n'
        )
        link_eigen = (
            "target_link_libraries(raisin_tf PUBLIC Eigen3::Eigen)"
            if uses_eigen
            else ""
        )
        package_eigen = "find_package(Eigen3 CONFIG REQUIRED)" if uses_eigen else ""
        install_eigen = (
            "raisin_install(raisin_tf Eigen3)"
            if uses_eigen
            else "raisin_install(raisin_tf)"
        )
        (producer / "CMakeLists.txt").write_text(
            "\n".join(
                [
                    "cmake_minimum_required(VERSION 3.14)",
                    "project(raisin_tf LANGUAGES CXX)",
                    f'set(RAISIN_MARCH "{march}")',
                    f'include("{HELPER}")',
                    package_eigen,
                    "add_library(raisin_tf SHARED source.cpp)",
                    link_eigen,
                    install_eigen,
                    "raisin_install_build_profile()",
                    "",
                ]
            )
        )
        build = root / "producer-build"
        prefix = root / "prefix"
        subprocess.run(
            ["cmake", "-S", str(producer), "-B", str(build)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["cmake", "--build", str(build)],
            check=True,
            capture_output=True,
            text=True,
        )
        install = subprocess.run(
            ["cmake", "--install", str(build), "--prefix", str(prefix)],
            check=False,
            capture_output=True,
            text=True,
        )
        if install.returncode:
            self.fail(install.stdout + install.stderr)
        if uses_eigen:
            eigen_install = prefix / "lib" / "cmake" / "Eigen3"
            eigen_install.mkdir(parents=True)
            (eigen_install / "Eigen3Config.cmake").write_text(
                "if(NOT TARGET Eigen3::Eigen)\n"
                "  add_library(Eigen3::Eigen INTERFACE IMPORTED)\n"
                "endif()\n"
            )
        return prefix

    def configure_consumer(
        self,
        root: Path,
        prefix: Path,
        expect_success: bool = True,
        allow_native: bool = False,
    ) -> str:
        consumer = root / f"consumer-{len(list(root.glob('consumer-*')))}"
        consumer.mkdir()
        (consumer / "main.cpp").write_text("int sdk_symbol(); int main() { return sdk_symbol(); }\n")
        (consumer / "CMakeLists.txt").write_text(
            "\n".join(
                [
                    "cmake_minimum_required(VERSION 3.14)",
                    "project(consumer LANGUAGES CXX)",
                    "find_package(raisin_tf CONFIG REQUIRED)",
                    "add_executable(probe main.cpp)",
                    "target_link_libraries(probe PRIVATE raisin_tf)",
                    "",
                ]
            )
        )
        build = root / f"{consumer.name}-build"
        command = [
            "cmake",
            "-S",
            str(consumer),
            "-B",
            str(build),
            "-DCMAKE_PREFIX_PATH=" + str(prefix),
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        ]
        if allow_native:
            command.append("-DRAISIN_ALLOW_UNPORTABLE_NATIVE_SDK=ON")
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        if expect_success and result.returncode:
            self.fail(result.stdout + result.stderr)
        if not expect_success:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout + result.stderr
        return (build / "compile_commands.json").read_text()

    def test_installed_target_propagates_explicit_cpu_profile(self):
        with tempfile.TemporaryDirectory(prefix="raisin-sdk-profile-") as tmp:
            root = Path(tmp)
            prefix = self.configure_and_install(root, "x86-64-v3")
            compile_commands = self.configure_consumer(root, prefix)
            commands = json.loads(compile_commands)
            self.assertIn("-march=x86-64-v3", commands[0]["command"])
            profile = json.loads(
                (prefix / "share" / "raisin" / "raisin-sdk-build-profile.json").read_text()
            )
            self.assertEqual(profile["cpu"]["march"], "x86-64-v3")
            self.assertEqual(profile["cpu"]["profile_kind"], "named-cpu-profile")
            self.assertEqual(profile["eigen"]["max_align_bytes"], 32)
            self.assertRegex(
                profile["eigen"]["core_header_and_usage_fingerprint_sha256"],
                r"^[0-9a-f]{64}$",
            )

    def test_non_eigen_target_does_not_constrain_consumer_cpu(self):
        with tempfile.TemporaryDirectory(prefix="raisin-sdk-non-eigen-") as tmp:
            root = Path(tmp)
            prefix = self.configure_and_install(root, "x86-64-v3", uses_eigen=False)
            commands = json.loads(self.configure_consumer(root, prefix))
            self.assertNotIn("-march=x86-64-v3", commands[0]["command"])

    def test_native_eigen_sdk_refuses_implicit_consumer_profile(self):
        with tempfile.TemporaryDirectory(prefix="raisin-sdk-native-") as tmp:
            root = Path(tmp)
            prefix = self.configure_and_install(root, "native")
            result = self.configure_consumer(root, prefix, expect_success=False)
            self.assertIn("RAISIN_ALLOW_UNPORTABLE_NATIVE_SDK=ON", result)
            compile_commands = json.loads(
                self.configure_consumer(root, prefix, allow_native=True)
            )
            self.assertIn("-march=native", compile_commands[0]["command"])
            profile = json.loads(
                (prefix / "share" / "raisin" / "raisin-sdk-build-profile.json").read_text()
            )
            self.assertEqual(profile["cpu"]["profile_kind"], "native-only")

    def test_consumer_rejects_mixed_eigen_cpu_profiles(self):
        with tempfile.TemporaryDirectory(prefix="raisin-sdk-mixed-profile-") as tmp:
            root = Path(tmp)
            producer = root / "producer"
            producer.mkdir()
            (producer / "include").mkdir()
            (producer / "source.cpp").write_text("int sdk_symbol() { return 0; }\n")
            eigen_config = root / "eigen-package" / "Eigen3Config.cmake"
            eigen_config.parent.mkdir()
            eigen_config.write_text(
                "if(NOT TARGET Eigen3::Eigen)\n"
                "  add_library(Eigen3::Eigen INTERFACE IMPORTED)\n"
                "endif()\n"
            )
            (producer / "CMakeLists.txt").write_text(
                "\n".join(
                    [
                        "cmake_minimum_required(VERSION 3.14)",
                        "project(raisin_tf LANGUAGES CXX)",
                        f'include("{HELPER}")',
                        "find_package(Eigen3 CONFIG REQUIRED)",
                        "add_library(raisin_tf_v3 SHARED source.cpp)",
                        "target_link_libraries(raisin_tf_v3 PUBLIC Eigen3::Eigen)",
                        'set(RAISIN_MARCH "x86-64-v3")',
                        "raisin_install(raisin_tf_v3 Eigen3)",
                        "add_library(raisin_tf_base SHARED source.cpp)",
                        "target_link_libraries(raisin_tf_base PUBLIC Eigen3::Eigen)",
                        'set(RAISIN_MARCH "x86-64")',
                        "raisin_install(raisin_tf_base Eigen3)",
                        "",
                    ]
                )
            )
            build = root / "producer-build"
            prefix = root / "prefix"
            subprocess.run(
                ["cmake", "-S", str(producer), "-B", str(build)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["cmake", "--build", str(build)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["cmake", "--install", str(build), "--prefix", str(prefix)],
                check=True,
                capture_output=True,
                text=True,
            )
            eigen_install = prefix / "lib" / "cmake" / "Eigen3"
            eigen_install.mkdir(parents=True)
            (eigen_install / "Eigen3Config.cmake").write_text(
                "if(NOT TARGET Eigen3::Eigen)\n"
                "  add_library(Eigen3::Eigen INTERFACE IMPORTED)\n"
                "endif()\n"
            )

            consumer = root / "consumer"
            consumer.mkdir()
            (consumer / "main.cpp").write_text("int main() { return 0; }\n")
            (consumer / "CMakeLists.txt").write_text(
                "\n".join(
                    [
                        "cmake_minimum_required(VERSION 3.20)",
                        "project(mixed_profile_consumer LANGUAGES CXX)",
                        "find_package(raisin_tf_v3 CONFIG REQUIRED)",
                        "find_package(raisin_tf_base CONFIG REQUIRED)",
                        "add_executable(probe main.cpp)",
                        "target_link_libraries(probe PRIVATE raisin_tf_v3 raisin_tf_base)",
                        "",
                    ]
                )
            )
            result = subprocess.run(
                [
                    "cmake",
                    "-S",
                    str(consumer),
                    "-B",
                    str(root / "consumer-build"),
                    "-DCMAKE_PREFIX_PATH=" + str(prefix),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("RAISIN_SDK_CPU_PROFILE", result.stdout + result.stderr)

    def test_nested_eigen_package_installs_root_build_profile(self):
        with tempfile.TemporaryDirectory(prefix="raisin-sdk-nested-profile-") as tmp:
            root = Path(tmp)
            producer = root / "producer"
            package = producer / "package"
            package.mkdir(parents=True)
            (package / "include").mkdir()
            (package / "source.cpp").write_text("int sdk_symbol() { return 0; }\n")
            eigen_package = root / "eigen-package"
            eigen_include = eigen_package / "include" / "Eigen"
            eigen_include.mkdir(parents=True)
            (eigen_include / "Core").write_text("#define EIGEN_MAX_ALIGN_BYTES 32\n")
            (eigen_package / "Eigen3Config.cmake").write_text(
                "if(NOT TARGET Eigen3::Eigen)\n"
                "  add_library(Eigen3::Eigen INTERFACE IMPORTED)\n"
                '  set_target_properties(Eigen3::Eigen PROPERTIES '
                f'INTERFACE_INCLUDE_DIRECTORIES "{eigen_include.parent}")\n'
                "endif()\n"
            )
            (producer / "CMakeLists.txt").write_text(
                "\n".join(
                    [
                        "cmake_minimum_required(VERSION 3.14)",
                        "project(nested_profile LANGUAGES CXX)",
                        'set(RAISIN_MARCH "x86-64-v3")',
                        f'include("{HELPER}")',
                        'add_subdirectory("package")',
                        "raisin_install_build_profile()",
                        "",
                    ]
                )
            )
            (package / "CMakeLists.txt").write_text(
                "\n".join(
                    [
                        "find_package(Eigen3 CONFIG REQUIRED)",
                        "add_library(raisin_tf SHARED source.cpp)",
                        "target_link_libraries(raisin_tf PUBLIC Eigen3::Eigen)",
                        "raisin_install(raisin_tf Eigen3)",
                        "",
                    ]
                )
            )
            build = root / "producer-build"
            prefix = root / "prefix"
            subprocess.run(
                [
                    "cmake",
                    "-S",
                    str(producer),
                    "-B",
                    str(build),
                    "-DEigen3_DIR=" + str(eigen_package),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["cmake", "--build", str(build)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["cmake", "--install", str(build), "--prefix", str(prefix)],
                check=True,
                capture_output=True,
                text=True,
            )
            profile = json.loads(
                (prefix / "share" / "raisin" / "raisin-sdk-build-profile.json").read_text()
            )
            self.assertEqual(profile["cpu"]["march"], "x86-64-v3")
            self.assertEqual(profile["eigen"]["max_align_bytes"], 32)


if __name__ == "__main__":
    unittest.main()
