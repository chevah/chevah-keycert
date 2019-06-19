# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
Common functions for the all classes from this package.

Forked from twisted.conch.ssh.common
"""

from __future__ import absolute_import, division

import struct
import sys


from cryptography.utils import int_from_bytes, int_to_bytes

_PY3 = sys.version_info > (3,)

if _PY3:  # pragma: no cover
    long = int
    unicode = str
    izip = zip

    def nativeString(s):
        return s.decode("ascii")

    def iterbytes(originalBytes):
        for i in range(len(originalBytes)):
            yield originalBytes[i:i + 1]
else:
    import itertools
    # So we can import from this module
    long = long
    unicode = unicode
    izip = itertools.izip

    def nativeString(s):
        return s

    def iterbytes(originalBytes):
        return originalBytes

if _PY3:
    from base64 import encodebytes
    from base64 import decodebytes
else:
    from base64 import encodestring as encodebytes
    from base64 import decodestring as decodebytes
encodebytes
decodebytes


def NS(t):
    """
    net string
    """
    if isinstance(t, unicode):
        t = t.encode("utf-8")
    return struct.pack('!L', len(t)) + t


def getNS(s, count=1):
    """
    get net string
    """
    ns = []
    c = 0
    for i in range(count):
        l, = struct.unpack('!L', s[c:c + 4])
        ns.append(s[c + 4:4 + l + c])
        c += 4 + l
    return tuple(ns) + (s[c:],)


def MP(number):
    if number == 0:
        return b'\000' * 4
    assert number > 0
    bn = int_to_bytes(number)
    if ord(bn[0:1]) & 128:
        bn = b'\000' + bn
    return struct.pack('>L', len(bn)) + bn


def getMP(data, count=1):
    """
    Get multiple precision integer out of the string.  A multiple precision
    integer is stored as a 4-byte length followed by length bytes of the
    integer.  If count is specified, get count integers out of the string.
    The return value is a tuple of count integers followed by the rest of
    the data.
    """
    mp = []
    c = 0
    for i in range(count):
        length, = struct.unpack('>L', data[c:c + 4])
        mp.append(int_from_bytes(data[c + 4:c + 4 + length], 'big'))
        c += 4 + length
    return tuple(mp) + (data[c:],)


def ffs(c, s):
    """
    first from second
    goes through the first list, looking for items in the second,
    returns the first one
    """
    for i in c:
        if i in s:
            return i
