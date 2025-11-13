#!/usr/bin/env python3
__version__ = '0.0.1'

import logging
import typing as t

import polyswarm_engine as psengine

if t.TYPE_CHECKING:
    from polyswarm_engine import Analysis, Bounty, Scanner

engine = psengine.EngineManager(
    name='jiangmin',
    vendor='Jiangmin',
    config=dict(SCANNER="./vendor/ConsoleScan.exe"),
)

log = logging.getLogger(__name__)


@engine.expose_command
def scan_file(filename: str):
    """Scan filename

    Output (stdout)
    --------------

        ConsoleScan from Jiangmin Co. Ltd. Version 1.0.0.0
        Scan Engine Version: 16.0.100
        Virus Library Date : 2021-11-01 21:20:18
        Find Virus EICAR-Test-File in Z:\\home\\zv\\Documents\\eicar.com
        Scan Complete

    """
    return psengine.spawn_subprocess(
        [engine.config["SCANNER"], str(psengine.as_nt_path(filename))],
        use_wine=True,
    )


@engine.register_analyzer
def analyze(bounty: "Bounty") -> "Analysis":
    with psengine.ArtifactTempfile(bounty) as path:
        scan = engine.cmd.scan_file(str(path))

        if 'Scan Complete' not in scan["stdout"]:
            return psengine.bounty.SKIPPED

        matches = dict(
            psengine.pattern_matches(
                scan["stdout"],
                (
                    r'Jiangmin Co. Ltd. Version (?P<analysis_engine_version>\S+)$'
                    r'^Scan Engine Version\s*:\s*(?P<analysis_definition_version>\S+)$',
                    r'^Virus Library Date\s*:\s*(?P<analysis_definition_timestamp>[0-9-]+( [0-9:]+)?)$',
                    r'^Find Virus (?P<malware_family>\S+)',
                ),
            )
        )

        scanner: "Scanner" = {
            "version": __version__,
            "vendor_version": matches.get("analysis_engine_version"),
            "signatures_version": matches.get("analysis_definition_version")
        }

        if "malware_family" in matches:
            return {
                "verdict": psengine.MALICIOUS,
                "metadata": {
                    "malware_family": matches.get("malware_family"),
                    "scanner": scanner
                }
            }
        elif any(matches):
            return {"verdict": psengine.BENIGN, "metadata": {"scanner": scanner}}
        else:
            return {"verdict": psengine.UNKNOWN, "metadata": {"scanner": scanner}}


if __name__ == "__main__":
    engine.cli()
