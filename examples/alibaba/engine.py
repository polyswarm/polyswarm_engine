#!/usr/bin/env python3

import json
import logging
import tempfile
import typing as t

import polyswarm_engine as psengine

if t.TYPE_CHECKING:
    from polyswarm_engine import Analysis, Bounty

log = logging.getLogger(__name__)

engine = psengine.EngineManager(
    name="Alibaba",
    vendor="Alibaba Group",
    config=dict(
        SCANNER="vendor/src/Win32/Release/alibaba.exe",
        SIGNATURES_DIR="vendor/def",
    )
)


@engine.register_head
def head():
    proc = engine.cmd.version()

    return dict(
        psengine.pattern_matches(
            proc["stdout"],
            [
                r"scanner version : (?P<engine_version>[\w.]+)",
                r"signatures version : (?P<definition_version>[\w.]+)",
            ],
        )
    )


@engine.register_analyzer
def analyze(bounty: "Bounty") -> "Analysis":
    with psengine.ArtifactTempfile(bounty) as path:
        proc = engine.cmd.scan_file(path)

        if proc["returncode"] == 0:
            scan_log = json.loads(proc["scan_log"])
            report = scan_log["report"]

            # This usually contains the correct name, but will be blank if a subreport fails.
            report_name = report.get("name")

            # Type of artifact detected
            report_type = report.get("type")

            # Individual "subreports", which contain the "score" and the correct name.
            subreports = report["local"], report["cloud"], dict(name=report_name)

            # Subreport scores range from 0 to 100 (-1 is used in special circumstances)
            scores = [(r.get("score", 0), r.get("name")) for r in subreports]

            # highest subreport's score & name
            score, name = max(scores, key=lambda tup: (tup[0], bool(tup[1])))

            analysis: "Analysis"

            if name:
                analysis = {
                    "verdict": psengine.MALICIOUS,
                    "metadata": {
                        "malware_family": name
                    },
                }

                alt_name = next((n for _, n in scores if n and n != name), None)
                if alt_name:
                    analysis["metadata"]["comments"] = [f"ALT_FAMILY_NAME={alt_name}"]
            elif report_type in {"unknown", "ignore"}:
                analysis = dict(verdict=psengine.UNKNOWN)
            else:
                analysis = dict(verdict=psengine.BENIGN)

            if report_type:
                analysis.setdefault("metadata", dict())
                analysis["metadata"].setdefault("comments", list())
                analysis["metadata"]["comments"].append(f"REPORT_TYPE={report_type}")

            if isinstance(score, int):
                analysis["bid"] = psengine.rescale_to_bid(bounty, score, min=0, max=100)
            else:
                analysis["bid"] = psengine.bid_min(bounty)

            return analysis
        else:
            raise RuntimeError("unexpected returncode: {}".format(proc["returncode"]))


@engine.expose_command
def version():
    """get engine/signature versions"""

    return psengine.spawn_subprocess(
        [engine.config["SCANNER"], "-b", engine.config["SIGNATURES_DIR"], "--version"],
        use_wine=True,
    )


@engine.expose_command
def scan_file(filename: "str"):
    """scan filename"""

    with tempfile.NamedTemporaryFile() as scan_log:
        proc = psengine.spawn_subprocess(
            [
                engine.config["SCANNER"],
                "-b",
                engine.config["SIGNATURES_DIR"],
                "-f",
                str(psengine.as_nt_path(filename)),
                "-l",
                str(psengine.as_nt_path(scan_log.name)),
            ],
            use_wine=True,
        )

        return {"scan_log": scan_log.read().decode(), **proc}


if __name__ == "__main__":
    engine.cli()
