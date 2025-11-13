import typing as t
import uuid
import base64

from .typing import AnalysisResult, ArtifactType

URL_MIMETYPE = "text/uri-list"

FILE_ARTIFACT: "ArtifactType" = "FILE"
URL_ARTIFACT: "ArtifactType" = "URL"
ARTIFACT_TYPES: "t.Set[ArtifactType]" = set(t.get_args(ArtifactType))

# Analysis Conclusions
BENIGN: "AnalysisResult" = "benign"
MALICIOUS: "AnalysisResult" = "malicious"
SUSPICIOUS: "AnalysisResult" = "suspicious"
UNKNOWN: "AnalysisResult" = "unknown"
AnalysisConclusions: "t.Set[AnalysisResult]" = set(t.get_args(AnalysisResult))

# These defined UUIDv5 namespaces are necessary to support the goal of semantic equivalence of some bounty objects.
# See: ``polyswarm_engine.bounty._forge_bounty_uuid``
BOUNTY_UUID = uuid.UUID("fafee1eb-ee7d-4b31-bee5-1547bd26c731")
FILE_BOUNTY_UUID = uuid.uuid5(BOUNTY_UUID, FILE_ARTIFACT)
URL_BOUNTY_UUID = uuid.uuid5(BOUNTY_UUID, URL_ARTIFACT)

SKIPPED_COMMENT = "SKIPPED"
SKIPPED_ENCRYPTED_COMMENT = f"{SKIPPED_COMMENT}:ENCRYPTED"
SKIPPED_HIGHCOMPRESSION_COMMENT = f"{SKIPPED_COMMENT}:DECOMPRESSION-UNSAFE"
SKIPPED_UNSUPPORTED_COMMENT = f"{SKIPPED_COMMENT}:TYPE-UNSUPPORTED"
SKIPPED_CANNOT_FETCH_COMMENT = f'{SKIPPED_COMMENT}:CANNOT-FETCH'

EICAR_CONTENT = base64.b64decode(
    b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='
)

# For easing the bid maths
NCT_TO_WEI_CONVERSION = 10**18
