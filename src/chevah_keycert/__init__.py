"""
SSL and SSH key management.
"""
from __future__ import absolute_import
import sys


def _path(path, encoding='utf-8'):
    if sys.platform.startswith('win'):
        # On Windows and OSX we always use unicode.
        return path  # pragma: no cover

    return path.encode(encoding)
