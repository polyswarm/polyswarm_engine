#!/usr/bin/env python3
__version__ = '1.0.0'

import logging
import typing as t

import polyswarm_engine as psengine

if t.TYPE_CHECKING:
    from polyswarm_engine import Analysis, Bounty

log = logging.getLogger(__name__)

engine = psengine.EngineManager(
    name="secureage",
    vendor="secureage",
    config={
        "SCANNER": "vendor/APEXScan.exe",
        "UPDATER": "vendor/APEXUpdate.exe",
    }
)


@engine.expose_command
def info():
    """Secureage version info"""
    return psengine.spawn_subprocess([engine.config["SCANNER"], "/version"], use_wine=True)


@engine.expose_command
def update():
    """Update engine signatures"""
    return psengine.spawn_subprocess([engine.config["UPDATER"]], use_wine=True)


@engine.expose_command
def scan_file(filename: str, polyswarm: bool = False):
    """Engine & signature versions

    Setting `polyswarm` will add the `/polyswarm` flag, which returns
    confidence instead of a result name.
    """
    cmdline = [engine.config["SCANNER"], f"/file={filename}"]

    if polyswarm:
        cmdline.append('/polyswarm')

    return psengine.spawn_subprocess(cmdline, use_wine=True)


@engine.register_head
def head():
    info = engine.cmd.info()
    return dict(
        psengine.pattern_matches(
            info["stdout"],
            [
                r"Engine version: (?P<engine_version>[0-9.]+)",
                r"APEX model version: (?P<definition_version>[0-9.]+)",
            ],
        )
    )


@engine.register_analyzer
def analyze(bounty: "Bounty") -> "Analysis":
    with psengine.ArtifactTempfile(bounty) as path:
        filename = str(path)
        scan = engine.cmd.scan_file(filename, polyswarm=True)
        stdout = scan["stdout"]
        matches = dict(
            psengine.pattern_matches(
                stdout, [
                    (
                        r"\A(?P<FILE>\S+?)\:\s*(%s)" % "|".join((
                            r"(Unable to scan \((?P<SCANFAIL>[^\r]+)\))",
                            r"(?P<ERRORCODE>Error code:[^\r]+)",
                            r"(?P<CONFIDENCE>\d+)",
                        ))
                    ),
                    r"^Model version: (?P<definition_version>[0-9.]+)$",
                    r"^Total unsafe files: (?P<INFECTED>[0-9]+) of (?P<SUPPORTED>[0-9]+)",
                    r"^Total unsupported files: (?P<UNSUPPORTED>[0-9]+)",
                ]
            )
        )

        if 'ERRORCODE' in matches:
            log.error("ERRORCODE in scan: %s", scan)
            return {"verdict": psengine.UNKNOWN}

        if 'SCANFAIL' in matches:
            if matches['SCANFAIL'] == 'format unsupported':
                return psengine.bounty.UNSUPPORTED
            else:
                log.error("Scan failed: %s", scan)
                return {"verdict": psengine.UNKNOWN}

        if int(matches['SUPPORTED']) == 0:
            return psengine.bounty.UNSUPPORTED

        confidence = int(matches['CONFIDENCE'])

        analysis: "Analysis" = {
            "verdict": psengine.UNKNOWN,
            "bid": psengine.rescale_to_bid(bounty, confidence, min=0, max=100)
        }

        if confidence > 50:
            analysis["verdict"] = psengine.MALICIOUS
            nscan = engine.cmd.scan_file(filename, polyswarm=False)["stdout"]

            try:
                end = nscan.index("\n")
                start = nscan[0:end].index(":") + 1
            except ValueError:
                pass
            else:
                if end > start:
                    malware_family = nscan[start:end].strip()
                    analysis["metadata"] = {"malware_family": malware_family}

            return analysis
        elif confidence > 0:
            analysis["verdict"] = psengine.BENIGN

        return analysis


if __name__ == "__main__":
    engine.cli()
