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


class BadKeyError(KeyCertException):
    """
    Raised when a key isn't what we expected from it.

    XXX: we really need to check for bad keys
    """


class EncryptedKeyError(KeyCertException):
    """
    Raised when an encrypted key is presented to fromString/fromFile without
    a password.
    """
