from __future__ import annotations
import contextlib
import logging
import typing as t
import copy
from urllib import parse
from datetime import datetime, timezone

import celery

from polyswarm_engine import exceptions
from polyswarm_engine.bounty import get_bounty_expiration, get_bounty_tasked_at, CANNOT_FETCH
from polyswarm_engine.settings import (
    PSENGINE_METADATA_ARCHTECTURE,
    PSENGINE_METADATA_OS,
    PSENGINE_DELIVERY_TASK,
    PSENGINE_DISCARD_EXPIRED_BOUNTIES,
)
from polyswarm_engine.constants import (
    BENIGN,
    MALICIOUS,
    SUSPICIOUS,
    UNKNOWN,
    AnalysisConclusions,
)

from polyswarm_engine.typing import Analysis
from polyswarm_engine.celeryconfig import CeleryConfig

logger = logging.getLogger(__name__)


def get_all_backend_names():
    """Used by internal tooling"""
    return ['CeleryBackend']


class CeleryBackend:
    app = None

    def __init__(
        self,
        name=None,
        analyze=None,
        head=None,
        lifecycle=contextlib.nullcontext,
        deliver_func=None,
        deliver_task_name=None,
    ):
        # lazy setting the backend
        if CeleryBackend.app is None:
            CeleryBackend.app = celery.Celery('polyswarm_engine_celery_backend', config_source=CeleryConfig())

        self.name = name
        self._analyze = analyze
        self._head = head
        self._lifecycle = lifecycle
        self.analysis_environment = None
        self._analyze_task = self._create_analyze_task()
        self._lifecycle_context = None

        self._deliver_task_name = deliver_task_name or PSENGINE_DELIVERY_TASK
        if self._deliver_task_name:
            self._deliver = deliver_func or self._queue_deliver
        else:
            self._deliver = deliver_func or self._http_deliver
        logger.debug("CeleryBackend deliver function: '%r'", self._deliver)

    def __repr__(self):
        return '{}(engine="{}")'.format(self.__class__.__name__, self.name)

    @contextlib.contextmanager
    def _run(self):
        with self._lifecycle():
            self.update_analysis_environment()
            logger.info("%r started", self)
            try:
                yield self
            finally:
                logger.info("%r stopped", self)

    def _enter(self, **_):
        logger.info('Setting up the lifecycle context for the forked worker.')
        self._lifecycle_context = self._run()
        try:
            return self._lifecycle_context.__enter__()
        except Exception as e:
            logger.warning('Could not start worker: %r', e, exc_info=True)
            raise celery.exceptions.WorkerShutdown from e

    def _exit(self, **_):
        logger.info('Cleaning up the lifecycle context for the forked worker.')
        result = self._lifecycle_context.__exit__(None, None, None)
        self._lifecycle_context = None
        return result

    @contextlib.contextmanager
    def run(self):
        # signals need to receive kwargs
        if CeleryBackend.app.conf.task_always_eager:
            self._enter()
            try:
                yield self
            finally:
                self._exit()
        else:
            celery.signals.worker_process_init.connect(self._enter)
            celery.signals.worker_process_shutdown.connect(self._exit)
            yield self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return None

    def head(self):
        head_ = self._head() if self._head else {}

        if PSENGINE_METADATA_ARCHTECTURE or PSENGINE_METADATA_OS:
            environment: dict = head_.setdefault('scanner', {}).setdefault('environment', {})
            if PSENGINE_METADATA_OS:
                environment.setdefault('operating_system', PSENGINE_METADATA_OS)
            if PSENGINE_METADATA_ARCHTECTURE:
                environment.setdefault('architecture', PSENGINE_METADATA_ARCHTECTURE)
        return head_

    def update_analysis_environment(self):
        self.analysis_environment = dict(product=self.name)
        self.analysis_environment.update(self.head())

    def validate_result(self, analysis: 'Analysis'):
        assert "verdict" in analysis, f"verdict is missing in analysis: {analysis}"
        assert analysis.get("verdict") in AnalysisConclusions, "invalid verdict: {} must be one of {}".format(
            analysis.get('verdict'), ','.join(AnalysisConclusions)
        )

        if analysis["verdict"] in [MALICIOUS, BENIGN]:
            assert "bid" in analysis and isinstance(
                analysis["bid"], int
            ), f"bid must be an int, got: {analysis.get('bid')}"
            assert analysis["bid"] > 0, \
                f"benign and malicious verdicts require a bid > 0.0. got: {analysis.get('bid')}"
        elif analysis["verdict"] in [SUSPICIOUS, UNKNOWN]:
            if "bid" in analysis:
                logger.info("suspicious and unknown verdicts should not have a bid, it will be ignored")

        def validate_optional_field(key, obj, expected_type):
            assert isinstance(
                obj.get(key), (type(None), expected_type)
            ), f"{key} must be a {expected_type}, got: {obj.get(key)}"

        validate_optional_field("vendor", analysis, str)
        validate_optional_field("author", analysis, str)
        validate_optional_field("metadata", analysis, dict)
        validate_optional_field("confidence", analysis, float)

        if "metadata" in analysis:
            metadata = analysis["metadata"]
            validate_optional_field("malware_family", metadata, str)
            validate_optional_field("product", metadata, str)
            validate_optional_field("heuristic", metadata, bool)
            validate_optional_field("scanner", metadata, dict)
            validate_optional_field("comments", metadata, list)

            if "scanner" in metadata:
                scanner = metadata["scanner"]
                validate_optional_field("vendor_version", scanner, str)
                validate_optional_field("signatures_version", scanner, str)
                validate_optional_field("version", scanner, str)
                validate_optional_field("environment", scanner, dict)

                if "environment" in scanner:
                    environment = scanner["environment"]
                    validate_optional_field("architecture", environment, str)
                    validate_optional_field("operating_system", environment, str)

    @staticmethod
    def merge_inner(x, y):
        rv = dict()
        rv.update(y)
        rv.update(x)

        for k in (x.keys() & y.keys()):
            if isinstance(x[k], t.Mapping) and isinstance(y[k], t.Mapping):
                rv[k] = CeleryBackend.merge_inner(x[k], y[k])

        return rv

    def generate_enriched_result(self, analysis):
        # Handle the case of pre-nested metadata keys
        if "metadata" in self.analysis_environment and isinstance(self.analysis_environment["metadata"], dict):
            return self.merge_inner(analysis, self.analysis_environment)
        else:
            return self.merge_inner(analysis, {"metadata": self.analysis_environment})

    def _get_callback_info(self, url) -> tuple[str, str, str]:
        """
        Grabs info from the response_url of bounties

        Returns a tuple with (task_type, bounty_id, nonce),
        where task_type should be the 'assertions' or 'votes' string.
        """
        url = parse.urlparse(url)
        _, _, _, bounty_id, task_type, _ = url.path.split('/')
        _, nonce = url.query.split('=')
        return task_type, bounty_id, nonce

    def _queue_deliver(self, bounty: dict, enriched_result: dict):
        """Defer the delivery of bounty results to a Celery task

        The task name comes from `deliver_task_name` instance init args
        and is formatted with `task_type` and `response_url` as context,
        allowing some limited dynamic choosing of the Celery task
        """
        response_url = bounty.get('response_url')
        if response_url:
            task_type, bounty_id, nonce = self._get_callback_info(response_url)
            enriched_result['bounty'] = bounty_id
            enriched_result['_nonce'] = [nonce]

            taskname = self._deliver_task_name.format(
                task_type=task_type,
                response_url=response_url,
            )
            CeleryBackend.app.send_task(
                taskname,
                args=(enriched_result,),
                queue=task_type,
            )

    def _http_deliver(self, bounty: dict, enriched_result: dict):
        """Produce the delivery of bounty results by using an HTTP call

        Fails silently if `response_url` is not available in the `bounty`,
        as it assumes this `bounty` to be a local test.
        """
        import requests

        response_url = bounty.get('response_url')
        if response_url:
            try:
                with _http_debug_wrapper():
                    response = requests.post(response_url, json=enriched_result)
                if logger.getEffectiveLevel() < logging.DEBUG:
                    logger.debug('request body: %s', response.request.body)
                    logger.debug('response body: %s', response.text)
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                logger.error('Request failed: %s %s', e.response.text, e)

    def process_bounty(self, bounty):
        tasked_at = get_bounty_tasked_at(bounty)
        expiration = get_bounty_expiration(bounty)
        processing_start = datetime.now(timezone.utc)
        if processing_start > expiration:
            if PSENGINE_DISCARD_EXPIRED_BOUNTIES.upper() in ('1', 'YES', 'TRUE'):
                raise exceptions.EngineTimeoutError(
                    'Current time %s is past expiration time %s',
                    processing_start.isoformat(),
                    expiration.isoformat(),
                )

        try:
            result = self._analyze(bounty)
        except exceptions.BountyException as err:
            result: dict = copy.deepcopy(CANNOT_FETCH)
            result.setdefault('metadata', {})['error'] = repr(err)

        enriched_result = self.generate_enriched_result(result)
        self.validate_result(enriched_result)

        self._deliver(bounty, enriched_result)
        return enriched_result

    def analyze(self, bounty, queue=None, **options):
        if not queue and not CeleryBackend.app.conf.task_always_eager:
            raise exceptions.EngineException('Celery backend needs a queue.')
        return self._analyze_task.apply_async(
            args=(bounty, ),
            queue=queue,
            **options,
        )

    def _create_analyze_task(self):
        @CeleryBackend.app.task(name='psengine.celery_backend.analyze_task')
        def analyze_task(bounty):
            return self.process_bounty(bounty)

        return analyze_task


@contextlib.contextmanager
def _http_debug():
    """
    Produce logs of HTTP calls

    Produces logs by manipulating `http.client.HTTPConnetion`,
    as suggested on https://github.com/urllib3/urllib3/issues/107#issuecomment-11690207
    """
    # You'll need to do this before urllib3 creates any http connection objects
    import http.client

    initial_debuglevel = http.client.HTTPConnection.debuglevel
    http.client.HTTPConnection.debuglevel = 5
    try:
        yield
    finally:
        http.client.HTTPConnection.debuglevel = initial_debuglevel


_http_debug_wrapper = _http_debug if logger.getEffectiveLevel() < logging.DEBUG else contextlib.nullcontext
