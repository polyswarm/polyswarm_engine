import contextlib
import functools
import hashlib
import logging
import os
import random
import pathlib
import tempfile
import typing as t
import urllib.request
import uuid
from datetime import datetime, timezone, timedelta

import requests

from .constants import (
    ARTIFACT_TYPES,
    FILE_ARTIFACT,
    FILE_BOUNTY_UUID,
    SKIPPED_COMMENT,
    SKIPPED_ENCRYPTED_COMMENT,
    SKIPPED_HIGHCOMPRESSION_COMMENT,
    SKIPPED_UNSUPPORTED_COMMENT,
    SKIPPED_CANNOT_FETCH_COMMENT,
    SUSPICIOUS,
    UNKNOWN,
    URL_ARTIFACT,
    URL_BOUNTY_UUID,
    URL_MIMETYPE,
)
from .typing import (
    Analysis,
    ArtifactType,
    Bid,
    Bounty,
    BountyMetadata,
    GenericPathLike,
)
from .utils import build_data_uri, guess_mimetype
from .exceptions import BountyFetchException

log = logging.getLogger(__name__)

# report an analysis was skipped
SKIPPED: 't.Final[Analysis]' = dict(
    verdict=UNKNOWN,
    bid=0,
    metadata=dict(comments=[SKIPPED_COMMENT]),
)

# report skipped analysis due to an encrypted artifact (e.g password protected archive)
ENCRYPTED: 't.Final[Analysis]' = dict(
    verdict=UNKNOWN,
    bid=0,
    metadata=dict(comments=[SKIPPED_ENCRYPTED_COMMENT]),
)

# report skipped analysis due to unsafe decompression requirements (e.g zip bombs)
UNSAFE_DECOMPRESSION: 't.Final[Analysis]' = dict(
    verdict=SUSPICIOUS,
    bid=0,
    metadata=dict(comments=[SKIPPED_HIGHCOMPRESSION_COMMENT]),
)

# report skipped analysis due to unrecognized or corrupt artifact
UNSUPPORTED: 't.Final[Analysis]' = dict(
    verdict=UNKNOWN,
    bid=0,
    metadata=dict(comments=[SKIPPED_UNSUPPORTED_COMMENT]),
)

# repost skipped analysis due to a non-fetchable artifact
CANNOT_FETCH: 't.Final[Analysis]' = dict(
    verdict=UNKNOWN,
    bid=0,
    metadata=dict(comments=[SKIPPED_CANNOT_FETCH_COMMENT]),
)


def get_bounty_tasked_at(bounty: Bounty, *, default_timedelta=timedelta(seconds=0)) -> datetime:
    return _get_bounty_datekey(bounty, datekey='tasked_at', default_timedelta=default_timedelta)


def get_bounty_expiration(bounty: Bounty, *, default_timedelta=timedelta(seconds=90)) -> datetime:
    return _get_bounty_datekey(bounty, datekey='expiration', default_timedelta=default_timedelta)


def _get_bounty_datekey(bounty: Bounty, datekey: str, *, default_timedelta=timedelta(seconds=90)) -> datetime:
    """Return a `datetime` for this bounty's expiration"""
    value = bounty.get(datekey)

    if not value:
        log.debug('No %s in bounty=%s', datekey, bounty)
        return datetime.now(timezone.utc) + default_timedelta
    elif isinstance(value, str):
        value = datetime.fromisoformat(value)
        value = value.astimezone(timezone.utc)
        return value
    elif isinstance(value, datetime):
        return value
    else:
        raise TypeError(f'Illegal bounty {datekey}', value, bounty)


def lookup_artifact_type(
    artifact_type,
    *,
    typemap={
        fn(t): t  # type: ignore
        for t in ARTIFACT_TYPES for fn in (str.lower, str.upper, str.capitalize, lambda x: x)
    },
) -> 'ArtifactType':
    """Map a case-insensitive `artifact_type` to correct value"""
    try:
        return typemap[artifact_type]
    except KeyError:
        log.exception("Illegal artifact_type='%s'", artifact_type)
        return artifact_type


def get_artifact_type(bounty: Bounty) -> 'ArtifactType':
    """Return the ``ArtifactType`` of ``Bounty``"""
    return lookup_artifact_type(bounty["artifact_type"])


def is_file_artifact(bounty: Bounty) -> bool:
    """Check if ``bounty`` is for a FILE artifact"""
    return get_artifact_type(bounty) == FILE_ARTIFACT


def is_url_artifact(bounty: Bounty) -> bool:
    """Check if ``bounty`` is for a URL artifact"""
    return get_artifact_type(bounty) == URL_ARTIFACT


def get_artifact_bytes(bounty: Bounty) -> bytes:
    """Read and return ``bounty``'s artifact as bytes."""
    local, path = _lookup_artifact_path(bounty)

    if local:
        return path.read_bytes()

    with contextlib.closing(get_artifact_stream(bounty)) as fp:
        return b''.join(_blocks_iter(fp))


def get_artifact_stream(bounty: Bounty) -> t.BinaryIO:
    """Return a `Path` pointing to a temporary file containing this bounty's contents.
    Return a readable, non-seekable binary stream."""
    local, path = _lookup_artifact_path(bounty)

    if local:
        return open(path, 'rb')

    return _open_artifact_uri(bounty)


def get_artifact_path(bounty: Bounty) -> pathlib.Path:
    """Copy ``bounty``'s artifact to a tmpfile & return a `Path` pointing to it."""
    local, path = _lookup_artifact_path(bounty)

    if not local:
        try:
            # otherwise, write the data directly to our temporary file
            with contextlib.closing(_open_artifact_uri(bounty)) as fp:
                with open(path, 'wb') as tfp:
                    for block in _blocks_iter(fp):
                        tfp.write(block)
        except requests.exceptions.HTTPError as err:
            log.warning('HTTPError fetching the artifact: %r', err)
            raise

    return path


@contextlib.contextmanager
def ArtifactTempfile(bounty: Bounty):
    """ContextManager to get a temporary filename to ``bounty``'s artifact

    .. example::

        >>> with ArtifactTempfile(eicar_bounty) as path:
        >>>     print(path)
        PosixPath('/tmp/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
    """
    try:
        try:
            yield get_artifact_path(bounty)
        except requests.exceptions.HTTPError as err:
            log.warning('HTTPError fetching the bounty: %r', err)
            raise BountyFetchException from err
    finally:
        bounty_cleanup(bounty)


def bounty_cleanup(bounty: Bounty):
    """Cleanup all temporary files created while handling this bounty"""

    with contextlib.suppress(FileNotFoundError):
        local, path = _lookup_artifact_path(bounty)

        if not local:
            os.unlink(path)


def forge_local_bounty(
    *,
    artifact_type: ArtifactType = FILE_ARTIFACT,
    artifact_uri: t.Optional[str] = None,
    metadata: 'BountyMetadata' = None,
    data: t.Optional[t.Union[str, bytes]] = None,
    path: t.Optional['GenericPathLike'] = None,
    stream: t.Optional[t.BinaryIO] = None,
    sha256: t.Optional[t.Union[str, bytes]] = None,
    mimetype: t.Optional[str] = None,
    min_allowed_bid: 'Bid' = int(0.0625 * 1e18),
    max_allowed_bid: 'Bid' = int(0.9999 * 1e18),
    expiration: t.Union[str, datetime, timedelta] = timedelta(seconds=30),
) -> 'Bounty':
    """Convenience method to forge mock `Bounty` for local testing

    Examples
    --------

    Providing `path` will produce a bounty with a `file://` artifact uri

        >>> forge_local_bounty(path='/usr/bin/ls', artifact_type='file')
        {'id': 4157832140, 'artifact_uri': 'file:///usr/bin/ls', 'artifact_type': 'file', 'sha256':
        'b1b249f39beaa9360abe95570560437f41e0a0f8bb7e3c74546078996d80c5ff', 'mimetype': 'application/x-pie-executable'}

    If `data` is available, but no `path` is provided, a `data:` URI will be generated instead.

        >>> forge_local_bounty(data=b'test', artifact_type='file')
        {'id': 3146510944, 'artifact_uri': 'data:text/plain;base64,dGVzdA==', 'artifact_type': 'file', 'sha256':
        '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'mimetype': 'text/plain'}
    """
    # Check the value of min_allowed_bid / max_allowed_bid
    assert min_allowed_bid > 0, f"min_allowed_bid ({min_allowed_bid}) must be larger than 0"
    assert max_allowed_bid > min_allowed_bid,\
        f"max_allowed_bid ({min_allowed_bid}) must be larger than min_allowed_bid ({min_allowed_bid})"

    artifact_type = lookup_artifact_type(artifact_type)

    # URL artifacts should always use the `URL_MIMETYPE`
    if artifact_type == URL_ARTIFACT:
        mimetype = URL_MIMETYPE

    # Handle file-like streams
    if stream is not None:
        data = b''.join(iter(stream.read, b''))

    tempfile = None
    if artifact_uri is not None:
        tempfile = ArtifactTempfile({
            'artifact_uri' : artifact_uri,
            'id': f'{random.random():0.10f}'[2:],
        })
        path = tempfile.__enter__()

        mimetype = mimetype or guess_mimetype(path)

    elif path is not None:
        # Convert str & os.PathLikes to `pathlib.Path`
        if not isinstance(path, pathlib.Path):
            path = pathlib.Path(path)

        # resolve this to it's abspath
        path = path.resolve()
        artifact_uri = path.as_uri()

        # data == True -> is from an HTTP location
        mimetype = mimetype or guess_mimetype(path)

    elif data is not None:
        if isinstance(data, str):
            data = data.encode()

        mimetype = mimetype or guess_mimetype(data)

        # Build a `data:` URI with a base64-encoded `data`
        artifact_uri = build_data_uri(data, mimetype)

    assert artifact_uri is not None, "Cannot build URI without 'path' or 'data'"

    # Create our SHA256 digest
    if sha256 is None:
        if data is None:
            data = path.read_bytes()

        sha256 = hashlib.sha256(data).hexdigest()  # type: ignore
    elif isinstance(sha256, bytes):
        sha256 = sha256.hex()

    assert len(sha256) == 64, "Invalid SHA256 digest"

    if isinstance(expiration, timedelta):
        duration = int(expiration.total_seconds())
        expiration = (datetime.now(timezone.utc) + expiration).isoformat()
    else:
        # For a fake, the standard should be ok.
        duration = 30

    assert isinstance(expiration, (datetime, str))

    return Bounty(
        id=_forge_bounty_id(artifact_type, sha256),
        artifact_uri=artifact_uri,
        artifact_type=artifact_type,
        metadata={
            'sha256': sha256,
            'mimetype': mimetype,
        },
        rules={
            "min_allowed_bid": min_allowed_bid,
            "max_allowed_bid": max_allowed_bid,
        },
        duration=duration,
        expiration=expiration,
    )


def _open_artifact_uri(bounty: Bounty) -> t.BinaryIO:
    """Return a stream of the contents of this bounty's `artifact_uri`"""
    uri = bounty['artifact_uri']
    uri_scheme = urllib.parse.urlsplit(uri).scheme

    if uri_scheme in {'data', 'file'}:
        return urllib.request.urlopen(uri)
    else:
        request = requests.get(uri, stream=True)
        request.raise_for_status()
        request.raw.decode_content = True
        return request.raw


def _forge_bounty_id(artifact_type: ArtifactType, sha256: str) -> int:
    """Convenience method to forge a mock bounty ID

    Distinct UUID namespaces are used for file & urls to distinguish between files *containing* a URL and the URL
    itself.
    """
    guid = _forge_bounty_uuid(artifact_type, sha256)
    # Return only the lower 32 bits of our UUID
    return guid.int & 0xffffffff


def _forge_bounty_uuid(artifact_type: ArtifactType, digest: str) -> "uuid.UUID":
    """Convenience method to forge a mock bounty UUID

    Distinct UUID namespaces are used for file & urls to distinguish between files *containing* a URL and the URL
    itself.
    """
    # The SHA256 cannot distinguish between Bounties on files *containing* a URL and actual URLs.
    if artifact_type == FILE_ARTIFACT:
        namespace = FILE_BOUNTY_UUID
    elif artifact_type == URL_ARTIFACT:
        namespace = URL_BOUNTY_UUID
    else:
        raise ValueError(f"Invalid artifact_type='{artifact_type}'")

    return uuid.uuid5(namespace, digest)


ARTIFACT_TMPDIR = None
ArtifactPathLookup = t.NamedTuple('ArtifactPathLookup', [('local', bool), ('path', pathlib.Path)])


def _lookup_artifact_path(bounty: Bounty) -> 'ArtifactPathLookup':
    # Just return the local path for file:// URLs. No sense in performing a copy unless requested.
    uri = urllib.parse.urlsplit(bounty['artifact_uri'])

    if uri.scheme == 'file':
        # `uri.path` contains a URL-encoded path, which we must decode.
        real_path = urllib.parse.unquote(uri.path)
        # If a file:// uri has been passed that doesn’t exist, `FileNotFoundError` is raised.
        return ArtifactPathLookup(local=True, path=pathlib.Path(real_path).resolve(strict=True))
    else:
        global ARTIFACT_TMPDIR

        if ARTIFACT_TMPDIR is None:
            ARTIFACT_TMPDIR = pathlib.Path(tempfile.gettempdir()).absolute()

        return ArtifactPathLookup(local=False, path=ARTIFACT_TMPDIR.joinpath('bounty-{id}'.format_map(bounty)))


def _blocks_iter(fp: t.BinaryIO, *, block_size: int = 4096) -> t.Iterator[bytes]:
    return iter(functools.partial(fp.read, block_size), b'')
