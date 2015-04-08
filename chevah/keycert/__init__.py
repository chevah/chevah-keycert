"""
SSL and SSH key management.
"""
import os
import sys


def _path(path, encoding):
    if os.name != 'posix' or sys.platform.startswith('darwin'):
        # On Windows and OSX we always use unicode.
        # We don't run yet tests on Windows and OSX.
        # pragma: no cover
        return path

    return path.encode('utf-8')
