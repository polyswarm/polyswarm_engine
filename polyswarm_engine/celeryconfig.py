import functools
import importlib

from celery.worker.consumer import mingle, gossip
from celery.worker.worker import WorkController

import polyswarm_engine.settings

# monkey patch to enable -Ofair, the most stable during our tests
_original_setup_defaults = WorkController.setup_defaults
@functools.wraps(WorkController.setup_defaults)
def _new_setup_defaults(self, *args, **kwargs):
    kwargs['optimization'] = 'fair'
    return _original_setup_defaults(self, *args, **kwargs)
WorkController.setup_defaults = _new_setup_defaults
# monkey patch to disable mingle and gossip
mingle.Mingle.compatible_transports = {}
gossip.Gossip.compatible_transports = {}

##########################################
# Celery Configuration
##########################################
# https://docs.celeryproject.org/en/stable/userguide/configuration.html
class CeleryConfig:
    def __init__(
        self,
        broker: str = None,
        vhost: str = None,
        **kwargs,
    ):
        # Needs to reload to address PSENGINE_TASK_ALWAYS_EAGER late changes
        importlib.reload(polyswarm_engine.settings)

        from polyswarm_engine.settings import (
            PSENGINE_BROKER_URL,
            PSENGINE_BROKER_VHOST,
            PSENGINE_WORKER_CONCURRENCY,
            PSENGINE_WORKER_MAX_TASKS_PER_CHILD,
            PSENGINE_WORKER_PREFETCH_MULTIPLIER,
            PSENGINE_TASK_ALWAYS_EAGER,
        )

        broker = PSENGINE_BROKER_URL
        vhost = PSENGINE_BROKER_VHOST

        self.broker_url = f'{broker}/{vhost}' if vhost else broker
        self.broker_heartbeat = None
        self.broker_connection_retry_on_startup = True
        self.result_backend = None
        self.task_ignore_result = True
        self.task_acks_late = True
        self.task_reject_on_worker_lost = True
        self.task_store_errors_even_if_ignored = False
        self.task_queue_max_priority = 10
        self.task_default_priority = 5
        self.worker_concurrency = PSENGINE_WORKER_CONCURRENCY
        self.worker_prefetch_multiplier = PSENGINE_WORKER_PREFETCH_MULTIPLIER
        self.worker_hijack_root_logger = False
        self.worker_max_tasks_per_child = PSENGINE_WORKER_MAX_TASKS_PER_CHILD
        self.worker_send_task_events = False
        self.worker_enable_remote_control = False
        self.worker_cancel_long_running_tasks_on_connection_loss = True
        self.task_always_eager = PSENGINE_TASK_ALWAYS_EAGER
        self.broker_transport_options = {
            'max_retries': 3,
            'interval_start': 0,
            'interval_step': 0.2,
            'interval_max': 0.5,
            'fanout_prefix': True,
            'fanout_patterns': True,
        }

        # Allows general settings override by user.
        # AT YOUR OWN RISK
        for k, v in kwargs.items():
            setattr(self, k, v)
