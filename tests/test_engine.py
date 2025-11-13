import sys
import pytest
import polyswarm_engine
from polyswarm_engine.constants import EICAR_CONTENT, FILE_ARTIFACT


def import_engine_app(app: str) -> 'polyswarm_engine.engine.EngineManager':
    """
    Imports and initializes an EngineManager
    """
    mod_name, export_name = app.split(':')

    if not all((mod_name, export_name)):
        raise ValueError("Illegal engine appspec: {}".format(app))

    if mod_name not in sys.modules:
        from importlib import import_module
        import_module(mod_name)

    return getattr(sys.modules[mod_name], export_name)


@pytest.fixture(params=['celery'])
def backend(request):
    engine = import_engine_app("tests.fixtures.engines.engine_fixture_1:engine")

    with engine.create_backend() as backend:
        assert engine.ctx["has_started"] is True
        assert engine.ctx["has_ended"] is False
        yield backend

    assert engine.ctx["has_ended"] is True


def test_scan(backend):
    bounty = polyswarm_engine.bounty.forge_local_bounty(data=EICAR_CONTENT, artifact_type=FILE_ARTIFACT)
    analysis = backend.analyze(bounty, queue='test').get()
    assert analysis["metadata"]["malware_family"] == "tset"
