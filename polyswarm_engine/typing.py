import os
import typing as t

if t.TYPE_CHECKING:
    import datetime as dt

AnalysisResult = t.Literal["benign", "malicious", "suspicious", "unknown"]
GenericPathLike = t.Union[str, os.PathLike]
ArtifactType = t.Literal["FILE", "URL"]
Bid = int
Duration = t.Union[int, float, str]
OperatingSystemName = t.Literal["linux", "darwin", "windows"]


class Bounty(t.TypedDict, total=False):
    id: int
    artifact_uri: str
    artifact_type: 'ArtifactType'
    response_url: t.Optional[str]
    metadata: 'BountyMetadata'
    rules: 'BountyRules'
    duration: t.Optional['Duration']
    expiration: t.Union['dt.datetime', str]
    tasked_at: t.Optional[t.Union['dt.datetime', str]]


class BountyMetadata(t.TypedDict, total=False):
    sha256: t.Optional[str]
    mimetype: t.Optional[str]


class BountyRules(t.TypedDict, total=False):
    max_allowed_bid: 'Bid'
    min_allowed_bid: 'Bid'


# XXX: This could be a dangerously named type
class Environment(t.TypedDict, total=False):
    architecture: t.Optional[str]

    # The operating system used for the dynamic analysis of the malware instance. This applies to virtualized operating
    # systems as well as those running on bare metal
    operating_system: t.Optional['OperatingSystemName']


class Scanner(t.TypedDict, total=False):
    environment: t.Optional['Environment']

    # The version of the analysis engine or product (including AV engines) that was used to perform the analysis.
    vendor_version: t.Optional[str]

    # The version of the analysis definitions used by the analysis tool (including AV tools).
    signatures_version: t.Optional[str]

    # The version of the PolySwarm engine wrapper
    version: t.Optional[str]


class AnalysisMetadata(t.TypedDict, total=False):
    # The name of the analysis engine or product that was used. Product names
    # SHOULD be all lowercase with words separated by a dash "-".
    product: str

    # The classification result or name assigned to the malware instance by the scanner tool.
    malware_family: t.Optional[str]

    # Captures comments regarding the analysis that was performed
    comments: t.List[str]

    scanner: t.Optional['Scanner']

    # indicator for assertions generated from heuristics
    heuristic: t.Optional[bool]


class Analysis(t.TypedDict, total=False):
    # Captures the conclusion of the analysis, such as whether the binary was found to be malicious.
    verdict: 'AnalysisResult'

    # Captures the relative measure of confidence in the accuracy of the analysis results.
    # The confidence value *MUST* be a float in the range of 0.0 ~ 1.0
    confidence: t.Optional[float]

    bid: t.Optional['Bid']
    metadata: t.Optional['AnalysisMetadata']

    # Specifies the name of the vendor of this analysis engine
    vendor: t.Optional[str]

    author: t.Optional[str]


class CompletedProcessDict(t.TypedDict, total=True):
    returncode: int
    args: t.Sequence[str]
    stdout: t.Optional[str]
    stderr: t.Optional[str]


class ApplyResult(t.Protocol):
    """The class of the result returned by BaseTaskBackend.apply_async()"""

    def get(self, timeout: float = None):
        ...

    def wait(self, timeout: float = None):
        ...

    def ready(self) -> bool:
        ...

    def successful(self) -> bool:
        ...


EngineHeadCallable = t.Callable[[], "AnalysisMetadata"]
EngineCheckCallable = t.Callable[["Bounty"], bool]
EngineAnalyzeCallable = t.Callable[["Bounty"], "Analysis"]
EngineCommandCallable = t.Callable

PollResultT = t.TypeVar('PollResultT')

PollTargetCallable = t.Callable[..., PollResultT]
PollStepCallable = t.Callable[[float], float]
PollCheckCallable = t.Callable[[PollResultT], bool]
