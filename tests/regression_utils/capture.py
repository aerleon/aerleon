# Copyright 2022 Jason Benterou. All Rights Reserved.
#
# Author: jtwb
"""Capture decorators fully capture the test output and compare it to a
reference file stored in the repo. The test is failed if output does not
match exactly.

While not the fastest to run, these tests are flexible, easy to implement,
and they describe a broad image of application behavior.

Test authors must carefully control any output non-determinism.

## Usage

To create a test that captures and compares stdout, annotate a test with
decorator @capture.stdout(). You may apply multple decorators to the same test.
This will capture standard output while the test is running and compare it
to a file in the test directory named "<test_filename>_<test_name>.ref".

Files written to disk by your test code can be captured using test annotation
@capture.file(pathlike) where pathlike refers to the target file. The
content that would have been written is compared with a file in the test
directory named "<test_filename>_<test_name>_<file_name>.ref".

Users may wish to place each test file in its own folder to avoid having an
excessive number of reference files in the same folder.
"""

from collections import defaultdict
from io import StringIO
import os
from functools import wraps
from unittest import mock

__all__ = ("files", "stdout", "stderr")


def mock_half_open(config):
    """
    This mock version of open() will pass through to __main__.open() unless the
    condition defined by 'predicate' is true.

    For example the caller may wish to intercept writes to specific files and can
    do so by providing a predicate that examines the arguments to open().
    """

    real_open = open
    inner_mocks = defaultdict(mock.mock_open)
    mock_open = mock.MagicMock(name="open", spec=open)
    predicate = config.predicate
    partition_key = config.partition_key

    def _open(*args, **kwargs):
        if predicate(*args, **kwargs):
            return inner_mocks[partition_key(*args, **kwargs)](*args, **kwargs)
        return real_open(*args, **kwargs)

    mock_open.side_effect = _open

    return mock_open, inner_mocks


def _collapse_mock_writes(open_mocks, key):
    return "".join([str(c[1][0]) for c in list(open_mocks[key]().write.mock_calls)])


def _normalize_path(path):
    return os.path.normcase(os.path.normpath(path))


def _name_from_path(path):
    return os.path.split(_normalize_path(path))[1]


def _testdir(func):
    return os.path.dirname(func.__code__.co_filename)


class OpenMockConfig:
    def __init__(self, filenames):
        def predicate(
            file,
            mode="r",
            buffering=-1,
            encoding=None,
            errors=None,
            newline=None,
            closefd=True,
            opener=None,
        ):
            return mode == "w" and any(
                _normalize_path(file) == _normalize_path(filename)
                or _name_from_path(file) == _name_from_path(filename)
                for filename in filenames
            )

        def partition_key(
            file,
            mode="r",
            buffering=-1,
            encoding=None,
            errors=None,
            newline=None,
            closefd=True,
            opener=None,
        ):
            def _filter(filename):
                return _normalize_path(file) == _normalize_path(filename) or _name_from_path(
                    file
                ) == _name_from_path(filename)

            return next(filter(_filter, filenames), None)

        self.predicate = predicate
        self.partition_key = partition_key


def files(filenames):
    def inner_decorator(func):
        @wraps(func)
        def inner(self, *args, **kwargs):
            mock_open_callable, inner_mocks = mock_half_open(OpenMockConfig(filenames=filenames))
            with mock.patch("builtins.open", mock_open_callable):
                retval = func(self, *args, **kwargs)

            failed_assertion = None
            for filename in filenames:
                file_base = ".".join([func.__qualname__, filename])
                file_ref = ".".join([file_base, "ref"])
                try:
                    with open(os.path.join(_testdir(func), file_ref), "r") as ref_file:
                        self.assertEqual(
                            ref_file.read(),
                            _collapse_mock_writes(inner_mocks, filename),
                        )
                except IOError:
                    try:
                        with open(
                            os.path.join(_testdir(func), ".".join([file_base, "actual"])),
                            "w",
                        ) as actual:
                            actual.write(_collapse_mock_writes(inner_mocks, filename))
                    except IOError:
                        # In this case the actual content was not written, but this is not critical.
                        # The user does not need to be warned here.
                        pass
                    finally:
                        failed_assertion = AssertionError(
                            "Assertion failed: reference file {file} is not available for test {testname}".format(
                                file=file_ref, testname=func.__qualname__
                            )
                        )
                except AssertionError as e:
                    try:
                        with open(
                            os.path.join(_testdir(func), ".".join([file_base, "actual"])),
                            "w",
                        ) as actual:
                            actual.write(_collapse_mock_writes(inner_mocks, filename))
                    except IOError:
                        # In this case the actual content was not written, but this is not critical.
                        # The user does not need to be warned here.
                        pass
                    finally:
                        failed_assertion = e
            if failed_assertion:
                raise failed_assertion
            return retval

        return inner

    return inner_decorator


def stdout(func):
    @wraps(func)
    def inner(self, *args, **kwargs):
        with mock.patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            retval = func(self, *args, **kwargs)
            if 'name' in kwargs:
                file_base = ".".join([kwargs['name'], "stdout"])
                
            else:
                file_base = ".".join([func.__qualname__, "stdout"])
            file_ref = ".".join([file_base, "ref"])
            try:
                with open(os.path.join(_testdir(func), file_ref), "r") as ref_file:
                    self.assertEqual(ref_file.read(), mock_stdout.getvalue())
            except IOError:
                try:
                    with open(
                        os.path.join(_testdir(func), ".".join([file_base, "actual"])),
                        "w",
                    ) as actual:
                        actual.write(mock_stdout.getvalue())
                except IOError:
                    # In this case the actual content was not written, but this is not critical.
                    # The user does not need to be warned here.
                    pass
                finally:
                    raise AssertionError(
                        "Assertion failed: reference file {file} is not available for test {testname}".format(
                            file=file_ref, testname=func.__qualname__
                        )
                    )
            except AssertionError as e:
                try:
                    with open(
                        os.path.join(_testdir(func), ".".join([file_base, "actual"])),
                        "w",
                    ) as actual:
                        actual.write(mock_stdout.getvalue())
                except IOError:
                    # In this case the actual content was not written, but this is not critical.
                    # The user does not need to be warned here.
                    pass
                finally:
                    raise e
            return retval

    return inner


def stderr(func):
    @wraps(func)
    def inner(self, *args, **kwargs):
        with mock.patch("sys.stderr", new_callable=StringIO) as mock_stderr:
            retval = func(self, *args, **kwargs)
            file_base = ".".join([func.__qualname__, "stderr"])
            file_ref = ".".join([file_base, "ref"])
            try:
                with open(os.path.join(_testdir(func), file_ref), "r") as ref_file:
                    self.assertEqual(ref_file.read(), mock_stderr.getvalue())
            except IOError:
                try:
                    with open(
                        os.path.join(_testdir(func), ".".join([file_base, "actual"])),
                        "w",
                    ) as actual:
                        actual.write(mock_stderr.getvalue())
                except IOError:
                    # In this case the actual content was not written, but this is not critical.
                    # The user does not need to be warned here.
                    pass
                finally:
                    raise AssertionError(
                        "Assertion failed: reference file {file} is not available for test {testname}".format(
                            file=file_ref, testname=func.__qualname__
                        )
                    )
            except AssertionError as e:
                try:
                    with open(
                        os.path.join(_testdir(func), ".".join([file_base, "actual"])),
                        "w",
                    ) as actual:
                        actual.write(mock_stderr.getvalue())
                except IOError:
                    # In this case the actual content was not written, but this is not critical.
                    # The user does not need to be warned here.
                    pass
                finally:
                    raise e
            return retval

    return inner
