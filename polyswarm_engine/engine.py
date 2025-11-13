from __future__ import annotations
import contextlib
import logging

from polyswarm_engine.backend import CeleryBackend
from polyswarm_engine.cli import engine_cli
from polyswarm_engine.command import CommandRegistry

logger = logging.getLogger(__name__)


class EngineManager:
    def __init__(self, name, vendor=None, config=None, backend_kwargs: dict = None, **kwargs):
        self.name: str = name
        self.vendor: str = vendor
        self.config = config or dict()
        self.ctx = dict()
        self.backend: CeleryBackend|None = None
        self.backend_kwargs = dict()
        self.cmd = CommandRegistry()
        # in case a lifecycle is not defined, use a nop context manager
        self._lifecycle = lambda: contextlib.nullcontext()
        self._head = None
        self._analyze = None

    def cli(self):
        engine_cli(prog_name=self.name, obj=self)

    @contextlib.contextmanager
    def create_backend(self):
        """
        Start with backend

        Example
        -------

            >>> with Engine.create_backend() as backend:
            >>>    ...
        """
        self.backend = CeleryBackend(
            self.name,
            self._analyze,
            self._head,
            self._lifecycle,
            **self.backend_kwargs,
        )
        with self.backend.run() as backend:
            yield backend
        self.backend = None

    def expose_command(self, func: "EngineCommandCallable"):
        """Decorate to expose an internal engine function"""
        self.cmd._add(func)
        return func

    def register_analyzer(self, func: "EngineAnalyzeCallable"):
        """Decorator used to register this engine's analyzer function

        Example::

            @engine.register_analyzer
            def analyze(bounty: polyswarm_engine.Bounty) -> polyswarm_engine.Analysis:
                result = engine.cmd.scan_stream(get_artifact_stream(bounty))

                analysis = {"verdict": polyswarm_engine.UNKNOWN}

                if result["is_malicious"]:
                    analysis["verdict"] = polyswarm_engine.MALICIOUS

                if "result_name" in result:
                    analysis["metadata"] = {"malware_family": result["result_name"]}

                return analysis
        """
        self._analyze = func
        return func

    def register_head(self, func: "EngineHeadCallable"):
        """Decorator used to gather engine metadata at startup

        Notes::

        This should decorate a function that gathers any data you'd
        like to include with your analyses, but which isn't produced
        as part of the scanning process such as:

            - Engine version
            - Signature version
            - Current environment

        Example::

            @engine.register_head
            def head() -> polyswarm_engine.AnalysisMetadata:
                info = engine.cmd.info()

                return {
                    "product": info["productName"],
                    "scanner": {
                        "vendor_version": info["productVersion"],
                        "signatures_version": info["vbaseVersion"],
                    }
                }
        """
        self._head = func
        return func

    def register_lifecycle_manager(self, func: "EngineLifecycleCallable"):
        """Wraps a function acting as a engine lifecycle ContextManager

        Example::

            @engine.register_lifecycle_manager
            def lifecycle(Engine):
                pid = run([Engine.config["DAEMON"], "--start"]) # Setup worker
                yield
                terminate(pid) # Worker has terminated, run cleanup code...
        """
        self._lifecycle = contextlib.contextmanager(func)
        return func


__all__ = ["EngineManager"]
