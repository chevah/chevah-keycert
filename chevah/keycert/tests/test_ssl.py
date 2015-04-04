# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
Test for SSL keys/cert management.
"""
from argparse import ArgumentParser, Namespace
from hashlib import sha1
from StringIO import StringIO
import base64
import sys
import textwrap

from chevah.empirical import mk, EmpiricalTestCase

from chevah.keycert.tests.helpers import CommandLineMixin


class Test_generate_ssl_key_certificate_signing_request_subparser(
        EmpiricalTestCase, CommandLineMixin):
    """
    Unit tests for generate_ssl_key_certificate_signing_request_subparser.
    """

    def setUp(self):
        super(Test_generate_ssh_key_subparser, self).setUp()
        self.parser = ArgumentParser(prog='test-command')
        self.subparser = self.parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')

    def test_common_name_required(self):
        """
        It can not be called without at least the common-name argument
        """
        generate_ssl_key_certificate_signing_request_subparser(
            self.subparser, 'key-gen')

        options = self.parseArguments(['key-gen'])


    def test_default(self):
        """
        It can be initiaized with only a subparser and sub-command name.
        """
        generate_ssl_key_certificate_signing_request_subparser(
            self.subparser, 'key-gen')

        options = self.parseArguments([
            'key-gen',
            '--common-name', 'domain.com',
            ])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key_file': None,
            'key_size': 2048,
            'key_type': 'rsa',
            }, options)

    def test_value(self):
        """
        Options are parsed form command line.
        """
        generate_ssl_key_certificate_signing_request_subparser(
            self.subparser, 'key-gen')

        options = self.parseArguments([
            'key-gen',
            '--key-file=id_dsa',
            '--key-size', '1024',
            '--key-type', 'dsa',
            ])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key_file': 'id_dsa',
            'key_size': 1024,
            'key_type': 'dsa',
            }, options)

    def test_default_overwrite(self):
        """
        You can change default values.
        """
        generate_ssl_key_certificate_signing_request_subparser(
            self.subparser, 'key-gen',
            default_key_size=1024,
            default_key_type='dsa',
            )

        options = self.parseArguments(['key-gen'])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key_file': None,
            'key_size': 1024,
            'key_type': 'dsa',
            }, options)
