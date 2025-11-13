import polyswarm_engine

engine = polyswarm_engine.EngineManager('test_engine_1', vendor='polyswarm')


@engine.register_lifecycle_manager
def lifecycle():
    engine.ctx["has_started"] = True
    engine.ctx["has_ended"] = False
    yield
    engine.ctx["has_started"] = False
    engine.ctx["has_ended"] = True


@engine.expose_command
def scan(filename: str):
    return ''.join(reversed(filename))


@engine.register_head
def head():
    return {"engine_version": "1.0"}


@engine.register_analyzer
def analyze(bounty):
    malware_family = engine.cmd.scan("test")
    return {
        "verdict": polyswarm_engine.MALICIOUS,
        "metadata": {"malware_family": malware_family},
        "bid": 1,
    }
