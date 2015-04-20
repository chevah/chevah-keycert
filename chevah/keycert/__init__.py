"""
SSL and SSH key management.
"""
import os
import sys


def _path(path, encoding):
    if os.name != 'posix' or sys.platform.startswith('darwin'):
        # On Windows and OSX we always use unicode.
        # We don't run yet tests on Windows and OSX.
        return path  # pragma: no cover

    return path.encode('utf-8')
