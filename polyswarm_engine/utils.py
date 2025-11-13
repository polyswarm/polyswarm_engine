import base64
import datetime as dt
from datetime import timezone as tz
import functools
import inspect
import logging
import os
import os.path
import re
import stat
import subprocess
import sys
import time
import typing as t

from .exceptions import EngineExpiredException, EngineMaxCallException
from .typing import GenericPathLike
from .wine import WINELOADER

if t.TYPE_CHECKING:
    from .engine import EngineManager
    from .typing import (
        CompletedProcessDict,
        PollCheckCallable,
        PollResultT,
        PollStepCallable,
        PollTargetCallable,
    )

logger = logging.getLogger(__name__)


def spawn_subprocess(args: t.Sequence[str], use_wine=False, text=True, **popen_kwargs) -> 'CompletedProcessDict':
    """Run the command described by args. Wait for command to complete, then return a `CompletedProcessDict`.

    :param args: Command arguments
    :param use_wine:
        If true, prefix `args` with the absolute path of ``WINELOADER``. Packaged WINE installations generally register
        a PE `binfmt <https://en.wikipedia.org/wiki/Binfmt_misc>`, however `use_wine` should *still* be provided if
        this command runs under WINE.
    :param popen_kwargs: Additional keyword args to pass to `subprocess.run`
    """
    if use_wine and sys.platform != "win32":
        if not WINELOADER:
            raise FileNotFoundError("wine not found")
        args = [WINELOADER, *args]

    # supply 'capture_output=True` unless 'stdout' or 'stderr' are provided.
    if 'stdout' not in popen_kwargs and 'stderr' not in popen_kwargs:
        popen_kwargs.setdefault('capture_output', True)

    popen_kwargs.setdefault('timeout', 30)

    # NOTE only use spawn if your command returns text
    if text:
        popen_kwargs['text'] = True
        popen_kwargs.setdefault('encoding', 'utf-8')
        popen_kwargs.setdefault('errors', 'ignore')
    else:
        popen_kwargs['text'] = False

    proc = subprocess.run(args, **popen_kwargs)

    return dict(
        returncode=proc.returncode,
        args=tuple(map(str, proc.args)),
        stdout=proc.stdout or None,
        stderr=proc.stderr or None,
    )


def pattern_matches(
    stream: str,
    patterns: t.Union[t.Iterator[str], t.Sequence[str]],
    in_order: bool = False,
    index: int = 0,
    flags: int = re.MULTILINE,
    foldspaces: bool = True,
):
    """Generic "search for pattern in stream, using index" behavior.

    :param stream:
        The string to match against

    :param patterns:
        A sequence of regular expressions whose regex groups (`(?P<GROUP_NAME>matches)`) will be extracted as a
        dictionary (as in `re.Match.groupdict`)

    :param in_order:
        Setting causes patterns to only match those patterns appearing *after* the last matching pattern.

    :param index:
        The index to begin searching for patterns

    :param foldspaces:
        Controls if tabs & spaces inside `str` patterns (ignores `re.Pattern`) match any number of tabs /or/ spaces.
    """
    string = stream[index:].replace("\r\n", os.linesep)

    if foldspaces:
        patterns = (re.sub(r'(?<!\[)[ \t]+(?!\])', r'[ \t]+', p) for p in patterns)

    pattern = re.compile('|'.join(map('(?:{})'.format, patterns)), flags=flags)

    # Update seek index if we've matched
    last_group_index = -1

    # Search, across lines if necessary
    for match in pattern.finditer(string):
        for group_name, value in match.groupdict(None).items():
            if group_name and value:
                group_index = pattern.groupindex[group_name]

                if in_order:
                    if group_index < last_group_index:
                        continue
                    last_group_index = group_index

                yield group_name, value


def get_func_name(f: t.Callable) -> str:
    module, export_name = get_func_qual(f)

    if module and export_name:
        return f"{module}.{export_name}"
    elif export_name:
        return export_name
    else:
        raise ValueError("Could not find function name")


def get_func_qual(func) -> t.Tuple[str, str]:
    """ Return the function import path (as a list of module names), and a name for the function. """
    # Unwrap `functools.partials`
    while hasattr(func, 'func'):
        func = func.func

    if hasattr(func, '__module__'):
        module = func.__module__
    else:
        try:
            module = inspect.getmodule(func)
        except TypeError:
            if hasattr(func, '__class__'):
                module = func.__class__.__module__
            else:
                module = 'unknown'
    if module is None:
        # Happens in doctests, eg
        module = ''
    elif module == '__main__':
        try:
            filename = os.path.abspath(inspect.getsourcefile(func))
        except:
            filename = None
        if filename is not None:
            # mangling of full path to filename
            parts = filename.split(os.sep)

            if parts[-1].startswith('<ipython-input'):
                # We're in a IPython (or notebook) session. parts[-1] comes
                # from func.__code__.co_filename and is of the form
                # <ipython-input-N-XYZ>, where:
                # - N is the cell number where the function was defined
                # - XYZ is a hash representing the function's code (and name).
                #   It will be consistent across sessions and kernel restarts,
                #   and will change if the function's code/name changes
                # We remove N so that cache is properly hit if the cell where
                # the func is defined is re-exectuted.
                # The XYZ hash should avoid collisions between functions with
                # the same name, both within the same notebook but also across
                # notebooks
                splitted = parts[-1].split('-')
                parts[-1] = '-'.join(splitted[:2] + splitted[3:])
            elif len(parts) > 2 and parts[-2].startswith('ipykernel_'):
                # In a notebook session (ipykernel). Filename seems to be 'xyz'
                # of above. parts[-2] has the structure ipykernel_XXXXXX where
                # XXXXXX is a six-digit number identifying the current run (?).
                # If we split it off, the function again has the same
                # identifier across runs.
                parts[-2] = 'ipykernel'
            filename = '-'.join(parts)
            if filename.endswith('.py'):
                filename = filename[:-3]
            module = '{}-{}'.format(module, filename)

    if hasattr(func, 'func_name'):
        name = func.func_name
    elif hasattr(func, '__name__'):
        name = func.__name__
    else:
        name = 'unknown'

    # XXX maybe add a warning here? this is a hack to detect functions not defined at the module-level
    if hasattr(func, 'func_globals') and name in func.func_globals:
        if func.func_globals[name] is not func:
            name = '%s-alias' % name

    if inspect.ismethod(func):
        # We need to add the name of the class
        if hasattr(func, 'im_class'):
            klass = func.im_class  # type: ignore
            module = '{}{}'.format(module, klass.__name__)

    return module, name


def build_data_uri(data: bytes, mimetype: t.Optional[str] = None) -> str:
    """Return a RFC2397-compatible "data" URI"""
    return "data:{};base64,{}".format(mimetype or "", base64.b64encode(data).decode("ascii"))


def guess_mimetype(data: t.Union[bytes, 'GenericPathLike']) -> str:
    """Guess the MIME type of a file based on its contents"""
    inputdata = data if isinstance(data, bytes) else None
    try:
        return subprocess.check_output(
            [
                "file",
                "--brief",
                "--mime-type",
                "-" if inputdata else str(data),
            ],
            input=inputdata,
            timeout=5,
        ).decode("ascii").strip() or None
    except FileNotFoundError as e:
        logger.error(e)
        return None


def is_fifo(path) -> bool:
    """Check if a path is a FIFO"""
    if isinstance(path, (str, os.PathLike)) and os.path.exists(path):
        return stat.S_ISFIFO(os.stat(path).st_mode)
    else:
        return False


def get_open_port() -> int:
    """Returns an open port"""
    import socket

    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def resource_path(*paths, where: str = None, strict: bool = False) -> str:
    """Return the absolute, resolved path relative to the caller's file

    Example
    -------

    If `resource_path` was called within the file `/tmp/test-engine/engine.py`:

        >>> resource_path("vendor/file")
        /tmp/test-engine/vendor/file

    Using `where` to manually specify the relative root file:

        >>> resource_path("other", where=__file__)
        /tmp/test-engine/other

    Notes
    -----

    The `strict` parameter is used from some engines to produce a warning missing files/folders which are required for
    correct operation of the engine. However, this has been removed because it breaks non-worker users of engines.
    """
    if where is None:
        import inspect

        try:
            caller = inspect.stack(context=1)[1]
            where = caller.filename
        finally:
            # NOTE: The documentation isn't detailed enough to determine if needed
            # see: https://docs.python.org/3/library/inspect.html#the-interpreter-stack
            del caller

    return os.path.realpath(os.path.join(os.path.dirname(where), *paths))


def poll(
    target: 'PollTargetCallable',
    args=(),
    kwargs=None,
    step: 't.Union[float, int]' = 1,
    timeout: 't.Optional[t.Union[int, float, dt.timedelta]]' = None,
    expiration: 't.Optional[dt.datetime]' = None,
    max_tries: 't.Optional[int]' = None,
    check_success: 'PollCheckCallable' = lambda x: x is not None,
    step_function: 'PollStepCallable' = lambda s: s,
    ignore_exceptions: 't.Tuple[t.Type[BaseException], ...]' = tuple(),
) -> 'PollResultT':
    """Poll by calling a target function until a certain condition is met.

    You must specify at least a target function to be called and the step --
    base wait time between each function call.

    :param args: Arguments to be passed to the target function

    :param kwargs: Keyword arguments to be passed to the target function

    :param step: Step defines the amount of time to wait (in seconds)

    :param timeout: The target function will be called until the time elapsed is
        greater than the maximum timeout (in seconds).

    :param expiration: The target function will be called until the time is after
        the expiration if non-`None`.

    :param max_tries: Maximum number of times the target function will be called
        before failing

    :param check_success: A callback function that accepts the return value of
        the target function. It should return true if you want the polling
        function to stop and return this value. It should return false if you
        want it to continue executing. The default is a callback that tests for
        truthiness (anything not False, 0, or empty collection).

    :param step_function: A callback function that accepts each iteration's
        "step." By default, this is constant, but you can also pass a function
        that will increase or decrease the step.

    :param ignore_exceptions: You can specify a tuple of exceptions that should
        be caught and ignored on every iteration. If the target function raises
        one of these exceptions, it will be caught and the exception instance
        will be pushed to the queue of values collected during polling. Any
        other exceptions raised will be raised as normal.

    :return: Polling will return first value from the target function that meets
        the condions of the check_success callback. By default, this will be the
        first value that is not None, 0, False, '', or an empty collection.


    Note
    ----

    The actual execution time of the function *can* exceed the time specified in
    the timeout or expiration. For instance, if the target function takes 10
    seconds to execute and the timeout is 21 seconds, the polling function will
    take a total of 30 seconds (two iterations of the target --20s which is less
    than the timeout--21s, and a final iteration).
    """
    assert expiration is not None or timeout is not None or max_tries is not None, \
        'You did not specify an expiration, maximum number of tries or a timeout.'

    if timeout is not None:
        if isinstance(timeout, (int, float)):
            timeout = dt.timedelta(seconds=timeout)

        timeout_dt = dt.datetime.now(tz.utc) + timeout

        if expiration is None:
            expiration = timeout_dt
        else:
            expiration = min(expiration, timeout_dt)
            logger.debug(f"Using minimum of expiration & timeout ({expiration:%c})")

    tries = 0
    kwargs = kwargs or dict()

    logger.debug("Begin polling on %s(expiration=%s, tries=%d, max_tries=%s)", target, expiration, tries, max_tries)

    last_item = None

    while True:
        if max_tries is not None and tries >= max_tries:
            raise EngineMaxCallException(last_item)

        try:
            val = target(*args, **kwargs)
            last_item = val
        except ignore_exceptions as e:
            last_item = e
            logger.error("poll() ignored exception %r", e)
        else:
            # Condition passes, this is the only "successful" exit from the polling function
            if check_success(val):
                logger.debug("Success, continuing %s(tries=%d)", target, tries)
                return val
            else:
                logger.debug("Failed, continuing %s(tries=%d)", target, tries)

        tries += 1
        logger.debug("%s(expiration=%s, tries=%d, max_tries=%s)", target, expiration, tries, max_tries)

        # Check the max tries at this point so it will not sleep before raising the exception
        if max_tries is not None and tries >= max_tries:
            raise EngineMaxCallException(last_item)

        # Check the time after to make sure the poll function is called at least once
        if expiration is not None and dt.datetime.now(tz.utc) >= expiration:
            raise EngineExpiredException(last_item)

        time.sleep(step)
        step = step_function(step)


def poll_decorator(
    extract_poll_kwargs: t.Optional[t.Tuple[str, ...]] = (
        "expiration",
        "max_tries",
        "step",
        "step_function",
        "timeout",
    ),
    **poll_kwargs,
):
    """Use poll() as a decorator.

    :param extract_poll_kwargs: Tuple of keys which are popped from the
        decorated wrapper function's keyword args (``kwargs``) and merged
        with the keyword args passed to `poll` (``poll_kwargs``).

    :return: decorator using poll()"""

    def decorator(target):

        @functools.wraps(target)
        def wrapper(*args, **kwargs):
            if extract_poll_kwargs:
                for poll_keyword in extract_poll_kwargs:
                    if poll_keyword in kwargs:
                        poll_kwargs[poll_keyword] = kwargs.pop(poll_keyword)

            return poll(target=target, args=args, kwargs=kwargs, **poll_kwargs)

        return wrapper

    return decorator
