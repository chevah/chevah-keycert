"""
SSL and SSH key management.
"""
from __future__ import absolute_import
import sys
import six


def _path(path, encoding='utf-8'):
    if sys.platform.startswith('win'):
        # On Windows we always use unicode.
        return path  # pragma: no cover

    if isinstance(path, six.binary_type):
        # Path is already encoded.
        return path

    return path.encode(encoding)


def native_string(string):
    """
    Helper for some API that need bytes on Py2 and Unicode on Py3.
    """
    if six.PY2:
        string = string.encode('ascii')
    return string
