"""
SSL and SSH key management.
"""
import sys


def _path(path, encoding='utf-8'):
    if sys.platform.startswith('win'):
        # On Windows and OSX we always use unicode.
        return path  # pragma: no cover

    return path.encode(encoding)
