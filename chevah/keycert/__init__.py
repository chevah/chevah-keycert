"""
SSL and SSH key management.
"""
import os
import sys


def _path(path, encoding):
    if os.name != 'posix' or sys.platform.startswith('darwin'):
        # On Windows and OSX we always use unicode.
        return path

    return path.encode('utf-8')
