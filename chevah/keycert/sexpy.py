# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
S-expression read / write.

Forked from twisted.conch.ssh.sexpy
"""

from chevah.keycert.common import _PY3


def parse(s):
    s = s.strip()
    expr = []
    while s:
        if s[0:1] == b'(':
            newSexp = []
            if expr:
                expr[-1].append(newSexp)
            expr.append(newSexp)
            s = s[1:]
            continue
        if s[0:1] == b')':
            aList = expr.pop()
            s = s[1:]
            if not expr:
                assert not s
                return aList
            continue
        i = 0
        while s[i:i + 1].isdigit():
            i += 1
        assert i
        length = int(s[:i])
        data = s[i + 1:i + 1 + length]
        expr[-1].append(data)
        s = s[i + 1 + length:]
    assert 0, "this should not happen"   # pragma: no cover


def pack(sexp):
    s = b''
    for o in sexp:
        if type(o) in (type(()), type([])):
            s += b'('
            s += pack(o)
            s += b')'
        else:
            if _PY3:
                s += ("%d" % len(o)).encode('ascii')
            else:
                s += b"%d" % len(o)
            s += b":" + o
    return s
