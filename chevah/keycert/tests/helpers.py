# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
Helpers for testing the project.
"""
from argparse import Namespace
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import sys
import collections

from unittest import TestCase


class KeyCertTestCase(TestCase):
    """
    Test case for KeyCert tests.
    """

    def assertStartsWith(self, start, source):
        """
        Raise AssertionError if `source` does not starts with `start`.
        """
        if not source.startswith(start):
            message = '%s does not starts with %s' % (
                repr(source), repr(start))
            raise AssertionError(message.encode('utf-8'))

    def assertIsEmpty(self, target):
        """
        Raise AssertionError if target is not empty.
        """
        if isinstance(target, collections.Iterable):
            iterator = iter(target)
            try:
                next(iterator)
            except StopIteration:
                pass
            else:
                message = 'Iterable is not empty.\n%s.' % target
                raise AssertionError(message.encode('utf-8'))
            return

        if len(target) != 0:
            message = 'Value is not empty.\n%s.' % (target)
            raise AssertionError(message.encode('utf-8'))

    def assertEndsWith(self, end, source):
        """
        Raise AssertionError if `source` does not ends with `end`.
        """
        if not source.endswith(end):
            message = '%s does not end with %s' % (repr(source), repr(end))
            raise AssertionError(message.encode('utf-8'))


class CommandLineMixin(object):
    """
    Helper to test command line tools.
    """
    def parseArguments(self, args):
        """
        Parse arguments and return options and captured stdout.
        """
        stdout = StringIO()
        stderr = StringIO()
        prev_stdout = sys.stdout
        prev_stderr = sys.stderr
        try:
            sys.stdout = stdout
            sys.stderr = stderr
            options = self.parser.parse_args(args)
            return options
        except SystemExit as error:  # pragma: no cover
            raise AssertionError(
                'Fail to parse %s\n-- stdout --\n%s\n-- stderr --\n%s' % (
                    error.code,
                    stdout.getvalue(),
                    stderr.getvalue(),
                    ))
        finally:
            # We don't revert to sys.__stdout__ and the test runner might
            # have injected its logger.
            sys.stdout = prev_stdout
            sys.stderr = prev_stderr

    def parseArgumentsFailure(self, args):
        """
        Parse arguments and capture exit_code and stderr.
        """
        stdout = StringIO()
        stderr = StringIO()
        prev_stdout = sys.stdout
        prev_stderr = sys.stderr
        try:
            sys.stdout = stdout
            sys.stderr = stderr
            self.parser.parse_args(args)
            raise AssertionError(   # pragma: no cover
                'Failure not triggered when parsing the arguments.')
        except SystemExit as error:
            return error.code, stderr.getvalue()
        finally:
            # We don't revert to sys.__stdout__ and the test runner might
            # have injected its logger.
            sys.stdout = prev_stdout
            sys.stderr = prev_stderr

    def assertNamespaceEqual(self, expected, actual):
        """
        Check that namespaces are equal.
        """
        namespace = Namespace(**expected)
        self.assertEqual(namespace, actual)
