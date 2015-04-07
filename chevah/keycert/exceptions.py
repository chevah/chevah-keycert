# Copyright (c) 2014 Adi Roiban.
# See LICENSE for details.
"""
Public exceptions raised by this package.
"""


class KeyCertException(Exception):
    """
    Generic exception raised by the package.
    """
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message.encode('utf-8')
