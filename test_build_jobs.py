"""Build parallelism must stay within both the host capacity and CI cap."""

import os
import unittest
from unittest.mock import patch

from commands.utils import get_build_jobs


class TestBuildJobs(unittest.TestCase):
    def build_jobs(self, *, cpu_count, qemu=False, configured_cap=None):
        environment = {}
        if configured_cap is not None:
            environment["RAISIN_MAX_JOBS"] = str(configured_cap)

        with (
            patch.dict(os.environ, environment, clear=True),
            patch("commands.utils.os.cpu_count", return_value=cpu_count),
            patch("commands.utils.is_qemu_emulated", return_value=qemu),
        ):
            return get_build_jobs()

    def test_native_build_uses_half_the_available_cpus(self):
        self.assertEqual(self.build_jobs(cpu_count=12), 6)

    def test_ci_cap_does_not_force_low_core_jetson_to_use_48_jobs(self):
        self.assertEqual(self.build_jobs(cpu_count=12, configured_cap=48), 6)

    def test_ci_cap_limits_a_high_core_builder(self):
        self.assertEqual(self.build_jobs(cpu_count=192, configured_cap=48), 48)

    def test_lower_operator_cap_is_respected(self):
        self.assertEqual(self.build_jobs(cpu_count=12, configured_cap=2), 2)

    def test_qemu_limit_is_preserved_under_a_higher_ci_cap(self):
        self.assertEqual(
            self.build_jobs(cpu_count=192, qemu=True, configured_cap=48), 4
        )

    def test_zero_cap_cannot_enable_ninja_unlimited_parallelism(self):
        self.assertEqual(self.build_jobs(cpu_count=12, configured_cap=0), 1)


if __name__ == "__main__":
    unittest.main()
