# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
Test for exceptions raise by this package.
"""
from chevah.empirical import mk

from chevah.keycert.exceptions import KeyCertException
from chevah.keycert.tests.helpers import KeyCertTestCase


class TestExceptions(KeyCertTestCase):
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

        self.assertEqual(message.encode('utf-8'), str(error))
