# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Common functions for the all classes from this package.

Forked from twisted.conch.ssh.common
"""

from __future__ import absolute_import, division
import struct

from cryptography.utils import int_from_bytes, int_to_bytes
import six
from six.moves import range


# Functions for dealing with Python 3's bytes type, which is somewhat
# different than Python 2's:
if six.PY3:
    def iterbytes(originalBytes):
        for i in range(len(originalBytes)):
            yield originalBytes[i:i+1]


    def intToBytes(i):
        return ("%d" % i).encode("ascii")


    def lazyByteSlice(object, offset=0, size=None):
        """
        Return a copy of the given bytes-like object.

        If an offset is given, the copy starts at that offset. If a size is
        given, the copy will only be of that length.

        @param object: C{bytes} to be copied.

        @param offset: C{int}, starting index of copy.

        @param size: Optional, if an C{int} is given limit the length of copy
            to this size.
        """
        view = memoryview(object)
        if size is None:
            return view[offset:]
        else:
            return view[offset:(offset + size)]


    def networkString(s):
        if not isinstance(s, unicode):
            raise TypeError("Can only convert text to bytes on Python 3")
        return s.encode('ascii')
else:
    def iterbytes(originalBytes):
        return originalBytes


    def intToBytes(i):
        return b"%d" % i

    lazyByteSlice = buffer

    def networkString(s):
        if not isinstance(s, str):
            raise TypeError("Can only pass-through bytes on Python 2")
        # Ensure we're limited to ASCII subset:
        s.decode('ascii')
        return s



def NS(t):
    """
    net string
    """
    if isinstance(t, six.text_type):
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
    goes through the first list, looking for items in the second, returns the first one
    """
    for i in c:
        if i in s:
            return i



def force_unicode(value):
    """
    Decode the `value` to unicode.

    It will try to extract the message from an exception.

    In case there are encoding errors when converting the invalid characters
    are replaced.
    """
    import errno

    def str_or_repr(value):

        if isinstance(value, six.text_type):
            return value

        try:
            return six.text_type(value, encoding='utf-8')
        except Exception:
            """
            Not UTF-8 encoded value.
            """

        try:
            return six.text_type(value, encoding='windows-1252')
        except Exception:
            """
            Not Windows encoded value.
            """

        try:
            return six.text_type(str(value), encoding='utf-8', errors='replace')
        except (UnicodeDecodeError, UnicodeEncodeError):
            """
            Not UTF-8 encoded value.
            """

        try:
            return six.text_type(
                str(value), encoding='windows-1252', errors='replace')
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass

        # No luck with str, try repr()
        return six.text_type(repr(value), encoding='windows-1252', errors='replace')

    if value is None:
        return u'None'

    if isinstance(value, six.text_type):
        return value

    if isinstance(value, EnvironmentError) and value.errno:
        # IOError, OSError, WindowsError.
        code = value.errno
        message = value.strerror
        # Convert to Unix message to help with testing.
        if code == errno.ENOENT:
            # On Windows it is:
            # The system cannot find the file specified.
            message = b'No such file or directory'
        if code == errno.EEXIST:
            # On Windows it is:
            # Cannot create a file when that file already exists
            message = b'File exists'
        if code == errno.EBADF:
            # On AIX: Bad file number
            message = b'Bad file descriptor'

        if code and message:
            if value.filename:
                return "[Errno %s] %s: '%s'" % (
                    code,
                    str_or_repr(message),
                    str_or_repr(value.filename),
                    )
            return '[Errno %s] %s.' % (code, str_or_repr(message))

    if isinstance(value, Exception):
        try:
            details = str(value)
        except (UnicodeDecodeError, UnicodeEncodeError):
            details = getattr(value, 'message', '')
        result = str_or_repr(details)
        if result:
            return result
        return str_or_repr(repr(value))

    return str_or_repr(value)
