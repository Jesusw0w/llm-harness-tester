"""The installed package matches the version declared in the source tree."""

from importlib.metadata import version

import inject_probe


def test_version_is_single_sourced() -> None:
    assert version("inject-probe") == inject_probe.__version__
