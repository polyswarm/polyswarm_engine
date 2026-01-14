from __future__ import annotations
import os
import platform
import shutil

#: The queue system URL used by Celery
PSENGINE_BROKER_URL = os.getenv('PSENGINE_BROKER_URL', 'amqp://user:password@rabbitmq:5672')
#: Default vhost if Celery is backed by RabbitMQ
PSENGINE_BROKER_VHOST = os.getenv('PSENGINE_BROKER_VHOST', 'engines')

#: Verbosity level for logs
LOG_LEVEL = os.getenv('LOG_LEVEL', 'WARNING')
if LOG_LEVEL.isnumeric():
    LOG_LEVEL = int(LOG_LEVEL)
#: Format of logs. 'json' is available, in adition to 'text'
LOG_FORMAT = os.getenv('LOG_FORMAT', 'text')

#: Path of the `wine` executable
WINELOADER: str | None = os.getenv('WINELOADER') or shutil.which('wine')
#: Path of the `wineserver` executable
WINESERVER: str | None = os.getenv('WINESERVER') or shutil.which('wineserver')
#: Path of the `winepath` command executable
WINEPATH_CMD: str | None = os.getenv('WINEPATH_CMD') or shutil.which('winepath')

#: Reported machine archtecture where the scanner runs
PSENGINE_METADATA_ARCHTECTURE: str = os.getenv('PSENGINE_METADATA_ARCHTECTURE', platform.machine())
#: Reported operational system where the scanner runs
PSENGINE_METADATA_OS = os.getenv('PSENGINE_METADATA_OS', platform.system())

#: Used to compute HMAC for PolySwarm bounties sent via HTTP
PSENGINE_WEBHOOK_SECRET = os.getenv('PSENGINE_WEBHOOK_SECRET')

# Celery Worker related configs.
# Names are prefixed to conflict not with user instances of Celery
PSENGINE_WORKER_CONCURRENCY: int = int(os.getenv('PSENGINE_WORKER_CONCURRENCY', '1'))
PSENGINE_WORKER_PREFETCH_MULTIPLIER: int = int(os.getenv('PSENGINE_WORKER_PREFETCH_MULTIPLIER', '1'))
PSENGINE_WORKER_MAX_TASKS_PER_CHILD: int = int(os.getenv('PSENGINE_WORKER_MAX_TASKS_PER_CHILD', '1000'))
PSENGINE_TASK_ALWAYS_EAGER: bool = bool(int(os.getenv('PSENGINE_TASK_ALWAYS_EAGER', '0')))

#: Name of the Celery task that processes the delivery of assertions and votes.
# If empty, fallback to doing the delivery directly via HTTP
PSENGINE_DELIVERY_TASK = os.getenv('PSENGINE_DELIVERY_TASK', '')

#: Turn on (set as 1) to discard bounties arrived after the expiration.
PSENGINE_DISCARD_EXPIRED_BOUNTIES = os.getenv('PSENGINE_DISCARD_EXPIRED_BOUNTIES', '')
