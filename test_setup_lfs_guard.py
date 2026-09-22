import pytest
from unittest.mock import patch

from commands import setup as setup_commands


class _guard_result:
    """Give the guard a fixed scan result, whatever workspace the run sits in."""

    def __init__(self, affected=(), unreadable=()):
        self._patches = [
            patch.object(
                setup_commands,
                "find_repos_with_lfs_pointers",
                return_value=(list(affected), list(unreadable)),
            ),
            patch.object(setup_commands, "get_repos_to_ignore", return_value=[]),
        ]

    def __enter__(self):
        for item in self._patches:
            item.start()
        return self

    def __exit__(self, *exc_info):
        for item in reversed(self._patches):
            item.stop()
        return False


def test_guard_passes_when_every_asset_is_materialized():
    with _guard_result():
        setup_commands.guard_src_repo_lfs_assets()


def test_guard_stops_and_names_the_repository_holding_pointers(capsys):
    with _guard_result(affected=[("raisin_raibo2", ["resource/mesh/TORSO.STL"])]):
        with pytest.raises(SystemExit) as exit_info:
            setup_commands.guard_src_repo_lfs_assets()

    assert exit_info.value.code == 1
    output = capsys.readouterr().out
    assert "raisin_raibo2: 1 file(s) [resource/mesh/TORSO.STL]" in output
    assert "git lfs install --local && git lfs fetch && git lfs checkout" in output
    assert "install_system_deps.sh" in output


def test_guard_stops_when_a_repository_could_not_be_scanned(capsys):
    with _guard_result(unreadable=[("raisin_gui", "git ls-files failed")]):
        with pytest.raises(SystemExit) as exit_info:
            setup_commands.guard_src_repo_lfs_assets()

    assert exit_info.value.code == 1
    assert "could not be scanned (git ls-files failed)" in capsys.readouterr().out


def test_no_way_past_the_guard_is_offered_on_the_command_line():
    """The guard is fail-closed, and nothing on the command line reopens it.

    A pointer stub survives configure, build and install untouched, so a way
    past the guard does not save the run -- it moves the failure to runtime,
    hours later and far from the cause.
    """
    from commands.build import build_cli_command

    for command in (setup_commands.setup_command, build_cli_command):
        options = {name for param in command.params for name in param.opts}
        assert "--allow-missing-lfs" not in options


def test_setup_stops_before_it_deletes_anything():
    """The guard has to run while the workspace is still whole.

    A few lines after it, setup() removes generated/ and install/ outright, so a
    guard placed any later would trade a broken run for a broken workspace.
    """
    with _guard_result(affected=[("raisin_raibo2", ["resource/mesh/TORSO.STL"])]):
        with patch.object(setup_commands, "delete_directory") as delete_directory:
            with pytest.raises(SystemExit):
                setup_commands.setup()

    delete_directory.assert_not_called()
