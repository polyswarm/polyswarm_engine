class EngineException(Exception):
    pass


class EngineTimeoutError(EngineException):
    pass


class EngineFileNotFoundError(EngineException):
    pass


class EngineWorkerInterrupt(EngineException):
    """ An exception that is not KeyboardInterrupt to allow subprocesses
        to be interrupted.
    """

    pass


class EnginePollingException(EngineException):
    """Base exception that stores all return values of attempted polls"""

    def __init__(self, last=None):
        self.last = last


class EngineExpiredException(EnginePollingException):
    """Exception raised if polling function times out"""


class EngineMaxCallException(EnginePollingException):
    """Exception raised if maximum number of iterations is exceeded"""


class BountyException(Exception):
    """Bounty had problems"""


class BountyFetchException(Exception):
    """Bounty artifact could not be fetched"""
