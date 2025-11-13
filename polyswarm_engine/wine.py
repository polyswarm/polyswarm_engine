import functools
import glob
import logging
import os
import os.path
import pathlib
import subprocess
import sys
import typing as t

from polyswarm_engine.settings import WINELOADER, WINESERVER, WINEPATH_CMD

log = logging.getLogger(__name__)


if sys.platform == 'win32':
    as_nt_path = pathlib.WindowsPath
    winepath = None
    spawn_persistent_wineserver = None
else:
    DeviceRoot = t.NamedTuple(
        'DeviceRoot',
        [('nt_drive', pathlib.PureWindowsPath), ('abspath', pathlib.PosixPath)],
    )

    _WINE_DOSDEVICE_ROOTS: t.Optional[t.List['DeviceRoot']] = None

    def winepath(
        path: t.Union[pathlib.PurePath, str], to: t.Type[t.Union[pathlib.PurePath, str]] = pathlib.PureWindowsPath
    ):
        """Convert a Unix path to/from a Win32 (short/long) path compatible with it's WinNT counterpart.

        Invoking `winepath` can be surprisingly expensive, so use `as_nt_path` where possible.
        """
        wants_posix_path = issubclass(to, pathlib.PurePosixPath) or isinstance(path, pathlib.PureWindowsPath)

        assert bool(WINEPATH_CMD), 'WINEPATH_CMD, usually `winepath`, should be set as the winepath command.'
        proc = subprocess.run(
            [
                WINEPATH_CMD,
                "-u" if wants_posix_path else "-w",
                os.fsdecode(path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True,
        )

        return to(proc.stdout.strip())

    def _find_wine_dosdevice_roots() -> t.List['DeviceRoot']:
        """
        Look through each of WINE's dosdevices symlinks (typically living in `$WINEPREFIX/dosdevices`), storing the
        (WinNT drive path/Unix path) for each & ordering from _most_ specific to _least_ specific Unix path.
        """
        global _WINE_DOSDEVICE_ROOTS

        if _WINE_DOSDEVICE_ROOTS is None:

            def devices_iter():
                for drive_link in winepath("C:/", to=pathlib.PosixPath).parent.glob("?:"):
                    if drive_link.is_symlink():
                        abspath: pathlib.PosixPath = drive_link.resolve()

                        if abspath.is_dir():
                            drive = winepath(abspath, to=pathlib.PureWindowsPath)
                            # Verify that `drive` matches the trailing drive stem
                            drive_letter = drive_link.stem[0]
                            assert drive == pathlib.PureWindowsPath("%s:/" % drive_letter)
                            yield DeviceRoot(nt_drive=drive, abspath=abspath)
                        else:
                            log.warning("Ignoring device root pointing to '%s'", abspath)

            @functools.cmp_to_key
            def cmp_path_rel(a, b):
                if a.abspath == b.abspath:
                    return 0

                return -1 if a.abspath.is_relative_to(b.abspath) else 1

            _WINE_DOSDEVICE_ROOTS = sorted(devices_iter(), key=cmp_path_rel)

        return _WINE_DOSDEVICE_ROOTS

    def as_nt_path(path: t.Union[str, pathlib.Path]) -> pathlib.PureWindowsPath:
        """Converts a Unix path to the corresponding WinNT path

        Faster than using `winepath`
        """
        path = pathlib.Path(path).resolve()

        for nt_drive, abspath in _find_wine_dosdevice_roots():
            try:
                subpath = path.relative_to(abspath)
            except ValueError:
                continue
            else:
                return nt_drive / subpath

        raise FileNotFoundError(f"Could not find a suitable NT path for '{path}'")

    def spawn_persistent_wineserver():
        # Search for the server's Unix socket, which is created in a subdirectory
        # generated from the WINEPREFIX directory device and inode numbers.
        sockets = glob.glob(f"/tmp/.wine-{os.getuid():d}/server*/socket")

        if any(sockets):
            log.debug("not starting wineserver, found existing (%s)", sockets)
        else:
            wservcmd = [WINESERVER, "--persistent", "--debug=0"]
            log.debug("wineserver starting: '%s'", " ".join(wservcmd))
            subprocess.check_call(wservcmd, stdout=subprocess.DEVNULL)

            # spawn test wine process, to kick off the server
            subprocess.check_call(
                [WINEPATH_CMD],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            log.info("started wineserver")


__all__ = ["WINELOADER", "WINESERVER", "as_nt_path", "winepath", "spawn_persistent_wineserver"]
