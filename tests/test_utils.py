import datetime as dt
import pathlib
import time
from unittest.mock import Mock, patch

import pytest

from polyswarm_engine import pattern_matches
import polyswarm_engine.utils
import polyswarm_engine.exceptions
from polyswarm_engine.utils import (
    build_data_uri,
    get_func_name,
    get_open_port,
    resource_path,
)


def fixture_func():
    pass


fixture_lambda = lambda: True


@pytest.mark.parametrize(
    'func,name',
    [
        (get_func_name, 'polyswarm_engine.utils.get_func_name'),
        (fixture_func, 'test_utils.fixture_func'),
        (fixture_lambda, 'test_utils.<lambda>'),
    ],
)
def test_get_func_name(func, name):
    assert get_func_name(func) == name


def test_build_data_uri():
    assert build_data_uri(b'hello') == "data:;base64,aGVsbG8="


BASIC_PATTERNS = [r"Hello: (?P<hello>\w+)", r"Goodbye: (?P<goodbye>\w+)"]


@pytest.mark.parametrize(
    'expected, matches', [
        [
            dict(hello="world", goodbye="test"),
            pattern_matches(
                "Hello: world\nGoodbye: test",
                patterns=BASIC_PATTERNS,
            ),
        ],
        [
            dict(hello="world", goodbye="test"),
            pattern_matches(
                "Hello: world\nGoodbye: test",
                patterns=reversed(BASIC_PATTERNS),
            ),
        ],
        [
            dict(hello="world", goodbye="test"),
            pattern_matches(
                "Hello: world\nGoodbye: test",
                patterns=BASIC_PATTERNS,
                in_order=True,
            ),
        ],
        [
            dict(hello="world"),
            pattern_matches(
                "Hello: world\nGoodbye: test",
                patterns=reversed(BASIC_PATTERNS),
                in_order=True,
            ),
        ],
        [
            dict(hello="world", goodbye="test"),
            pattern_matches(
                "Hello: \t  world\nGoodbye: \t  test",
                patterns=BASIC_PATTERNS,
            ),
        ],
        [
            dict(hello="world", goodbye="test"),
            pattern_matches(
                "Hello:   world\nGoodbye: test",
                patterns=BASIC_PATTERNS,
            ),
        ],
        [
            dict(goodbye="test"),
            pattern_matches(
                "Hello:   world\nGoodbye: test",
                patterns=BASIC_PATTERNS,
                foldspaces=False,
            ),
        ],
        [
            dict(goodbye="test"),
            pattern_matches(
                "Hello:\tworld\nGoodbye: test",
                patterns=[r"Hello:[ ](?P<hello>\w+)", r"Goodbye: (?P<goodbye>\w+)"],
            ),
        ],
        [
            dict(multiline="multiple\nlines", therest="the rest"),
            pattern_matches(
                "start:multiple\nlines and the rest\n",
                patterns=[r"start:(?P<multiline>[a-z]+$\n^[a-z]+)", r" and (?P<therest>.*)"],
            )
        ],
        [
            dict(therest="the rest"),
            pattern_matches(
                "start:multiple\nlines and the rest\n",
                patterns=[r"start:(?P<multiline>[a-z]+$\n^[a-z]+)", r" and (?P<therest>.*)"],
                flags=0,
            )
        ],
    ]
)
def test_pattern_matches(expected, matches):
    assert dict(matches) == expected


def test_get_open_port():
    import socket
    port = get_open_port()

    # Should be able to listen on `port`
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", port))
        s.listen(1)

        # Should raise "Address already in use"
        with pytest.raises(OSError):
            with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as ns:
                ns.bind(("127.0.0.1", port))
                ns.listen(1)

    # Should not raise "Address already in use"
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", port))
        s.listen(1)


def test_resource_path():
    basedir = pathlib.Path(__file__).parent
    assert isinstance(resource_path("test"), str)

    test = pathlib.Path(resource_path("test"))
    assert test.name == "test"
    assert test == basedir / "test"
    assert str(test) == resource_path("test", where=__file__)
    assert str(test) != resource_path("test", where="another.py")

    subtest = pathlib.Path(resource_path("test/subtest"))
    assert subtest == basedir / "test" / "subtest"
    assert subtest.name == "subtest"
    assert subtest.parent.name == "test"


class TestPoll(object):

    def test_import(self):
        """Test that you can import via correct usage"""
        import polyswarm_engine
        from polyswarm_engine import poll, poll_decorator

        assert poll
        assert polyswarm_engine
        assert poll_decorator

    def test_arg_no_arg(self):
        """Tests various permutations of calling with invalid args"""
        with pytest.raises(TypeError):
            polyswarm_engine.utils.poll()

    def test_decorator_arg_no_arg(self):
        with pytest.raises(TypeError):

            @polyswarm_engine.utils.poll_decorator
            def throwaway():
                pass

            throwaway()

    def test_arg_no_step(self):
        with pytest.raises(TypeError):
            polyswarm_engine.utils.poll(lambda: 1 + None, max_tries=2)

    def test_decorator_arg_no_step(self):
        with pytest.raises(TypeError):

            @polyswarm_engine.utils.poll_decorator
            def throwaway():
                pass

            throwaway()

    def test_valid_arg_options(self):
        # Valid options
        polyswarm_engine.utils.poll(lambda: True, step=1, timeout=dt.timedelta(seconds=1))

        @polyswarm_engine.utils.poll_decorator(step=1, timeout=dt.timedelta(seconds=1))
        def throwaway():
            return True

        throwaway()

        polyswarm_engine.utils.poll(lambda: True, step=1, max_tries=1)

        @polyswarm_engine.utils.poll_decorator(step=1, max_tries=1)
        def throwaway():
            return True

        throwaway()

        polyswarm_engine.utils.poll(lambda: True, step=1, timeout=dt.timedelta(seconds=1), max_tries=1)

        @polyswarm_engine.utils.poll_decorator(step=1, timeout=dt.timedelta(seconds=1), max_tries=1)
        def throwaway():
            return True

        throwaway()

    @patch('time.sleep', return_value=None)
    @patch('time.time', return_value=0)
    def test_timeout_exception(self, patch_sleep, patch_time):

        # Since the timeout is < 0, the first iteration of polling should raise the error if max timeout < 0
        try:
            polyswarm_engine.utils.poll(target=lambda: None, step=10, timeout=dt.timedelta(seconds=1))
        except polyswarm_engine.exceptions.EngineExpiredException as e:
            assert e.last is None, 'The last value was incorrect'
        else:
            assert False, 'No timeout exception raised'

        # Test happy path timeout
        val = polyswarm_engine.utils.poll(lambda: True, step=0, timeout=dt.timedelta(seconds=0))
        assert val is True, 'Val was: {} != {}'.format(val, True)

    @patch('time.sleep', return_value=None)
    @patch('time.time', return_value=0)
    def test_decorator_timeout_exception(self, patch_sleep, patch_time):

        # Since the timeout is < 0, the first iteration of polling should raise the error if max timeout < 0
        try:

            @polyswarm_engine.utils.poll_decorator(step=10, timeout=dt.timedelta(seconds=0))
            def throwaway():
                return None

            throwaway()
        except polyswarm_engine.exceptions.EngineExpiredException as e:
            assert e.last is None, 'The last value was incorrect'
        else:
            assert False, 'No timeout exception raised'

        # Test happy path timeout
        @polyswarm_engine.utils.poll_decorator(step=0, timeout=dt.timedelta(seconds=0))
        def throwaway():
            return True

        val = throwaway()
        assert val is True, 'Val was: {} != {}'.format(val, True)

    def test_max_call_exception(self):
        """
        Test that a MaxCallException will be raised
        """
        tries = 100
        try:
            polyswarm_engine.utils.poll(lambda: False, step=0, max_tries=tries, check_success=bool)
        except polyswarm_engine.exceptions.EngineMaxCallException as e:
            assert e.last is False, 'The last value was incorrect'
        else:
            assert False, 'No MaxCallException raised'

    def test_decorator_max_call_exception(self):
        """
        Test that a MaxCallException will be raised
        """
        tries = 100
        try:

            @polyswarm_engine.utils.poll_decorator(step=0, max_tries=tries, check_success=bool)
            def throwaway():
                return False

            throwaway()
        except polyswarm_engine.exceptions.EngineMaxCallException as e:
            assert e.last is False, 'The last value was incorrect'
        else:
            assert False, 'No MaxCallException raised'

    def test_max_call_no_sleep(self):
        """
        Test that a MaxCallException is raised without sleeping after the last call
        """
        tries = 2
        sleep = 0.1
        start_time = time.time()

        with pytest.raises(polyswarm_engine.exceptions.EngineMaxCallException):
            polyswarm_engine.utils.poll(lambda: False, step=sleep, max_tries=tries, check_success=bool)
        assert time.time() - start_time < tries * sleep, 'Poll function slept before MaxCallException'

    def test_decorator_max_call_no_sleep(self):
        """
        Test that a MaxCallException is raised without sleeping after the last call
        """
        tries = 2
        sleep = 0.1
        start_time = time.time()

        with pytest.raises(polyswarm_engine.exceptions.EngineMaxCallException):

            @polyswarm_engine.utils.poll_decorator(step=sleep, max_tries=tries, check_success=bool)
            def throwaway():
                return False

            throwaway()
        assert time.time() - start_time < tries * sleep, 'Poll function slept before MaxCallException'

    def test_ignore_specified_exceptions(self):
        """
        Test that ignore_exceptions tuple will ignore exceptions specified.
        Should throw any errors not in the tuple.
        """
        # raises_errors is a function that returns 3 different things, each time it is called.
        # First it raises a ValueError, then EOFError, then a TypeError.
        raises_errors = Mock(return_value=True, side_effect=[ValueError, EOFError, RuntimeError])
        with pytest.raises(RuntimeError):
            # We are ignoring the exceptions other than a TypeError.
            polyswarm_engine.utils.poll(
                target=raises_errors, step=0.1, max_tries=3, ignore_exceptions=(ValueError, EOFError)
            )
        assert raises_errors.call_count == 3

    def test_decorator_ignore_specified_exceptions(self):
        """
        Test that ignore_exceptions tuple will ignore exceptions specified.
        Should throw any errors not in the tuple.
        """
        # raises_errors is a function that returns 3 different things, each time it is called.
        # First it raises a ValueError, then EOFError, then a TypeError.
        raises_errors = Mock(return_value=True, side_effect=[ValueError, EOFError, RuntimeError])
        # Seems to be an issue on python 2 with functools.wraps and Mocks(). See https://stackoverflow.com/a/22204742/4498470
        # Just going to ignore this until someone complains.
        raises_errors.__name__ = 'raises_errors'
        with pytest.raises(RuntimeError):
            # We are ignoring the exceptions other than a TypeError.
            # Note, instead of using @, calling poll_decorator like a traditional function.
            polyswarm_engine.utils.poll_decorator(
                step=0.1, max_tries=3, ignore_exceptions=(ValueError, EOFError)
            )(target=raises_errors)()
        assert raises_errors.call_count == 3

    def test_decorator_uses_wraps(self):
        """
        Test that the function name is not replaced when poll_decorator() is used.
        Thus we should be using functools.wraps() correctly.
        """

        @polyswarm_engine.utils.poll_decorator(step=0.1, max_tries=1)
        def throwaway():
            """Is the doc retained?"""
            return True

        assert throwaway.__name__ == 'throwaway', 'decorated function name has changed'
        assert throwaway.__doc__ == 'Is the doc retained?', 'decorated function doc has changed'
