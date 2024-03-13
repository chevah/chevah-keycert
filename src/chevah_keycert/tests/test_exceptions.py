# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
Test for exceptions raise by this package.
"""
from __future__ import absolute_import

from chevah_compat.testing import ChevahTestCase, mk

from chevah_keycert.exceptions import KeyCertException


class TestExceptions(ChevahTestCase):
    """
    Test for exceptions
    """

    def test_KeyCertException(self):
        """
        It provides a message.
        """
        message = mk.string()

        error = KeyCertException(message)

        self.assertEqual(message, error.message)

    def test_KeyCertException_str(self):
        """
        The message is the string serialization.
        """
        message = mk.string()

        error = KeyCertException(message)

        self.assertEqual(message, str(error))
