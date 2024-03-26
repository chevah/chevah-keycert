"""
SSL and SSH key management.
"""

import base64
import collections
import inspect
import sys

import cryptography.utils
import six


def _path(path, encoding="utf-8"):
    if sys.platform.startswith("win"):
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
        string = string.encode("ascii")
    return string


for member in ["Callable", "Iterable", "Mapping", "Sequence"]:
    if not hasattr(collections, member):
        setattr(collections, member, getattr(collections.abc, member))

if not hasattr(cryptography.utils, "int_from_bytes"):
    cryptography.utils.int_from_bytes = int.from_bytes

if not hasattr(base64, "encodestring"):
    base64.encodestring = base64.encodebytes

if not hasattr(base64, "decodestring"):
    base64.decodestring = base64.decodebytes

if not hasattr(inspect, "getargspec"):
    inspect.getargspec = lambda func: inspect.getfullargspec(func)[:4]
