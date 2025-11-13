import os.path
import pathlib

import pytest

from polyswarm_engine.wine import (
    WINELOADER,
    _find_wine_dosdevice_roots,
    as_nt_path,
    winepath,
)

wine_unavailable = WINELOADER is None
WINEPREFIX = os.path.expanduser("~/.wine/drive_c")


@pytest.mark.skipif(wine_unavailable, reason="WINE not available")
def test_find_dosdevice_roots():
    assert _find_wine_dosdevice_roots() == [
        (pathlib.PureWindowsPath("C:\\"), pathlib.PosixPath(WINEPREFIX)),
        (pathlib.PureWindowsPath("Z:\\"), pathlib.PosixPath("/")),
    ]


@pytest.mark.skipif(wine_unavailable, reason="WINE not available")
@pytest.mark.parametrize(
    'path,expected', [
        ("/tmp/test", pathlib.PureWindowsPath("Z:\\tmp\\test")),
        (WINEPREFIX + '/windows/regedit.exe', pathlib.PureWindowsPath("C:\\windows\\regedit.exe")),
    ]
)
def test_as_nt_path(path, expected):
    actual = as_nt_path(path)
    assert actual == expected
    assert actual == winepath(path)
