from __future__ import annotations
import contextlib
import io
try:
    import pathlib3x as pathlib
except ImportError:
    import pathlib
import sys

import pytest

import polyswarm_engine.bounty
from polyswarm_engine.constants import FILE_ARTIFACT, URL_ARTIFACT


@pytest.fixture
def artifact_tmpdir(monkeypatch, tmpdir):
    path = pathlib.Path(tmpdir)
    monkeypatch.setattr(polyswarm_engine.bounty, 'ARTIFACT_TMPDIR', path)
    yield path


@pytest.fixture(
    params=[
        pytest.param({"data": b"test data"}, id="FILE-data-test"),
        pytest.param({"data": b"DATA" * 999}, id="FILE-data-big"),
        pytest.param({"path": __file__}, id="FILE-path-__file__"),
        pytest.param({"path": sys.executable}, id="FILE-path-python"),
        pytest.param(
            {
                "__mkstream__": lambda: io.BytesIO(b"test"),
            },
            id="FILE-stream-test",
        ),
        pytest.param({"__mkstream__": lambda: open(sys.executable, 'rb')}, id="FILE-stream-python"),
        pytest.param(
            {
                "data": b"https://polyswarm/test",
                "artifact_type": URL_ARTIFACT
            },
            id="URL-data-test",
        ),
    ],
)
def artifact(request):
    d = request.param.copy()
    d.setdefault("artifact_type", FILE_ARTIFACT)
    stream = None

    if "__mkstream__" in d:
        streamfn = d.pop('__mkstream__')
        with contextlib.closing(streamfn()) as fp:
            d["content"] = fp.read()
        d["stream"] = streamfn()

    if "content" not in d:
        if "path" in d:
            d["content"] = pathlib.Path(d["path"]).read_bytes()
        elif "data" in d:
            d["content"] = d["data"]

    yield d

    if "stream" in d:
        d["stream"].close()


@pytest.fixture
def bounty(artifact, artifact_tmpdir):
    kwargs = artifact.copy()
    del kwargs["content"]
    bounty = polyswarm_engine.bounty.forge_local_bounty(**kwargs)
    local, path = polyswarm_engine.bounty._lookup_artifact_path(bounty)

    if local:
        assert bounty["artifact_uri"].startswith("file:")
        assert path.exists()
        yield bounty
        assert path.exists()
    else:
        assert not bounty["artifact_uri"].startswith("file:")
        assert not path.exists()
        # Verify that the path we get is within the tmpdir we set
        assert path.is_relative_to(artifact_tmpdir)
        yield bounty
        assert not path.exists()


def test_get_artifact_bytes(artifact, bounty):
    # Make sure we don't write this bounty's data to disk while fetching it's bytes
    assert polyswarm_engine.bounty.get_artifact_bytes(bounty) == artifact['content']


def test_ArtifactTempfile(artifact, bounty):
    with polyswarm_engine.bounty.ArtifactTempfile(bounty) as filename:
        path = pathlib.Path(filename)
        with open(filename, 'rb') as f:
            assert f.read() == artifact["content"]
        assert path.exists()


def test_get_artifact_stream(artifact, bounty):
    with polyswarm_engine.bounty.get_artifact_stream(bounty) as stream:
        assert stream.read() == artifact["content"]


def test_unique_forge_local_bounty_id():
    """Check that distinct bounties are built from identical artifacts w/ different artifact_types"""
    data = b"DATA"
    url_bounty = polyswarm_engine.bounty.forge_local_bounty(data=data, artifact_type=URL_ARTIFACT)
    file_bounty = polyswarm_engine.bounty.forge_local_bounty(data=data, artifact_type=FILE_ARTIFACT)
    assert url_bounty["id"] != file_bounty["id"]

    file_path = polyswarm_engine.bounty._lookup_artifact_path(file_bounty).path
    url_path = polyswarm_engine.bounty._lookup_artifact_path(url_bounty).path
    assert file_path != url_path


@pytest.mark.parametrize(
    'artifact_type,expected',
    [
        (FILE_ARTIFACT, FILE_ARTIFACT),
        (URL_ARTIFACT, URL_ARTIFACT),
        ("file", FILE_ARTIFACT),
        ("url", URL_ARTIFACT),
        ("File", FILE_ARTIFACT),
        ("Url", URL_ARTIFACT),
        ("FILE", FILE_ARTIFACT),
        ("URL", URL_ARTIFACT),
        # Failed cases
        ("", ""),
        (None, None),
        ("Fail", "Fail"),
        ("FiLe", "FiLe"),
        ("uRL", "uRL")
    ]
)
def test_lookup_artifact_type(artifact_type, expected):
    assert polyswarm_engine.bounty.lookup_artifact_type(artifact_type) == expected


@pytest.mark.parametrize('artifact_type, expected', [(FILE_ARTIFACT, True), (URL_ARTIFACT, False)])
def test_is_file_artifact(artifact_type, expected):
    assert (
        polyswarm_engine.bounty.is_file_artifact(
            polyswarm_engine.bounty.forge_local_bounty(artifact_type=artifact_type, data=b'')
        )
        is expected
    )


@pytest.mark.parametrize('artifact_type, expected', [(FILE_ARTIFACT, False), (URL_ARTIFACT, True)])
def test_is_url_artifact(artifact_type, expected):
    assert (
        polyswarm_engine.bounty.is_url_artifact(
            polyswarm_engine.bounty.forge_local_bounty(artifact_type=artifact_type, data=b'')
        )
        is expected
    )
