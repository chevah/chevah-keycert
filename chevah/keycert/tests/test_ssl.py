# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
Test for SSL keys/cert management.
"""
from argparse import ArgumentParser

from chevah.empirical import mk, EmpiricalTestCase
from OpenSSL import crypto

from chevah.keycert.exceptions import KeyCertException
from chevah.keycert.ssl import (
    generate_and_store_csr,
    generate_csr,
    generate_csr_parser,
    generate_ssl_self_signed_certificate,
    )
from chevah.keycert.tests.helpers import CommandLineMixin


class CommandLineTestBase(EmpiricalTestCase, CommandLineMixin):
    """
    Share code for testing methods which read SSL command line input.
    """

    def setUp(self):
        super(CommandLineTestBase, self).setUp()
        self.parser = ArgumentParser(prog='test-command')
        subparser = self.parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')
        self.command_name = 'gen-csr'
        generate_csr_parser(subparser, self.command_name)


class Test_generate_ssl_self_signed_certificate(EmpiricalTestCase):
    """
    Unit tests for generate_ssl_self_signed_certificate.
    """

    def test_generate(self):
        """
        Will generate the key and self signed certificate for current
        hostname.
        """
        cert_pem, key_pem = generate_ssl_self_signed_certificate()

        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        self.assertEqual(1024, key.bits())
        self.assertEqual(crypto.TYPE_RSA, key.type())
        subject = cert.get_subject()
        self.assertEqual(u'UN', subject.C)
        issuer = cert.get_issuer()
        self.assertEqual(cert.subject_name_hash(), issuer.hash())


class Test_generate_csr_parser(
        EmpiricalTestCase, CommandLineMixin):
    """
    Unit tests for generate_csr_parser.
    """

    def setUp(self):
        super(Test_generate_csr_parser, self).setUp()
        self.parser = ArgumentParser(prog='test-command')
        self.subparser = self.parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')

    def test_common_name_required(self):
        """
        It can not be called without at least the common-name argument
        """
        generate_csr_parser(self.subparser, 'key-gen')

        code, error = self.parseArgumentsFailure(['key-gen'])

        self.assertStartsWith('usage: test-command key-gen [-h]', error)
        self.assertEndsWith(
            '\ntest-command key-gen: '
            'error: argument --common-name is required\n',
            error)

    def test_default(self):
        """
        It can be initiaized with only a subparser and sub-command name.
        """
        generate_csr_parser(self.subparser, 'key-gen')

        options = self.parseArguments([
            'key-gen',
            '--common-name', 'domain.com',
            ])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key_file': 'server.key',
            'key_size': 2048,
            'key_type': 'rsa',
            'key_password': None,
            'common_name': 'domain.com',
            'alternative_name': None,
            'email': None,
            'organization': None,
            'organization_unit': None,
            'locality': None,
            'state': None,
            'country': None,
            }, options)

    def test_value(self):
        """
        Options are parsed form command line.
        """
        generate_csr_parser(self.subparser, 'key-gen')

        options = self.parseArguments([
            'key-gen',
            '--common-name', 'sub.domain.com',
            '--key-file=my_server.pem',
            '--key-size', '1024',
            '--key-type', 'dsa',
            '--key-password', u'valu\u20ac',
            '--alternative-name', 'DNS:www.domain.com,IP:127.0.0.1',
            '--email', 'admin@domain.com',
            '--organization', 'OU Name',
            '--organization-unit=OU Unit',
            '--locality=somewhere',
            '--state=without',
            '--country=GB',
            ])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key_file': 'my_server.pem',
            'key_size': 1024,
            'key_type': 'dsa',
            'key_password': u'valu\u20ac',
            'common_name': 'sub.domain.com',
            'alternative_name': 'DNS:www.domain.com,IP:127.0.0.1',
            'email': 'admin@domain.com',
            'organization': 'OU Name',
            'organization_unit': 'OU Unit',
            'locality': 'somewhere',
            'state': 'without',
            'country': 'GB',
            }, options)

    def test_default_overwrite(self):
        """
        You can change default values.
        """
        generate_csr_parser(
            self.subparser, 'key-gen',
            default_key_size=1024,
            default_key_type='dsa',
            )

        options = self.parseArguments([
            'key-gen',
            '--common-name', 'domain.com',
            ])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key_file': 'server.key',
            'key_size': 1024,
            'key_type': 'dsa',
            'key_password': None,
            'common_name': 'domain.com',
            'alternative_name': None,
            'email': None,
            'organization': None,
            'organization_unit': None,
            'locality': None,
            'state': None,
            'country': None,
            }, options)


class Test_generate_csr(CommandLineTestBase):
    """
    Unit tests for generate_csr.
    """

    def test_unknown_key(self):
        """
        Raise an exception when requested to generate a key with unknown type.
        """
        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            '--key-type=no-such-type',
            ])

        with self.assertRaises(KeyCertException) as context:
            generate_csr(options)

        self.assertEqual('Unknown key type.', context.exception.message)

    def test_bad_size(self):
        """
        Raise an exception when failing to generate the key.
        """
        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            '--key-type=rsa',
            '--key-size=12',
            ])

        with self.assertRaises(KeyCertException) as context:
            generate_csr(options)

        self.assertEqual('key size too small', context.exception.message)

    def test_bad_county_long(self):
        """
        Raise an exception when country code is not correct.
        """
        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            '--country=USA',
            ])

        with self.assertRaises(KeyCertException) as context:
            generate_csr(options)

        self.assertEqual('string too long', context.exception.message)

    def test_bad_county_short(self):
        """
        Raise an exception when country code is not correct.
        """
        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            '--country=A',
            ])

        with self.assertRaises(KeyCertException) as context:
            generate_csr(options)

        self.assertEqual('string too short', context.exception.message)

    def test_default_gen(self):
        """
        By default it will serialized the key without password and generate
        the csr without alternative name and just the common name.
        """
        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            ])

        result = generate_csr(options)

        # OpenSSL.crypto.PKey has no equality so we need to compare the
        # serialization.
        self.assertEqual(2048L, result['key'].bits())
        self.assertEqual(crypto.TYPE_RSA, result['key'].type())
        key = crypto.dump_privatekey(crypto.FILETYPE_PEM, result['key'])
        self.assertEqual(key, result['key_pem'])
        # For CSR we can not get extensions so we only check the subject.
        csr = crypto.dump_certificate_request(
            crypto.FILETYPE_PEM, result['csr'])
        self.assertEqual(csr, result['csr_pem'])
        subject = result['csr'].get_subject()
        self.assertEqual(u'domain.com', subject.commonName)
        self.assertIsNone(subject.emailAddress)
        self.assertIsNone(subject.organizationName)
        self.assertIsNone(subject.organizationalUnitName)
        self.assertIsNone(subject.localityName)
        self.assertIsNone(subject.stateOrProvinceName)
        self.assertIsNone(subject.countryName)

    def test_gen_unicode(self):
        """
        Domains are encoded using IDNA and names using unicode.
        """
        options = self.parseArguments([
            self.command_name,
            u'--common-name=domain-\u20acuro.com',
            u'--key-size=512',
            u'--key-type=rsa',
            u'--alternative-name=DNS:www.domain-\u20acuro.com,IP:127.0.0.1',
            u'--email=name@domain-\u20acuro.com',
            u'--organization=OU Nam\u20acuro',
            u'--organization-unit=OU Unit\u20acuro',
            u'--locality=Som\u20acwhere',
            u'--state=Stat\u20ac',
            u'--country=GB',
            ])

        result = generate_csr(options)

        csr = crypto.dump_certificate_request(
            crypto.FILETYPE_PEM, result['csr'])
        self.assertEqual(csr, result['csr_pem'])
        subject = result['csr'].get_subject()
        self.assertEqual(u'xn--domain-uro-x77e.com', subject.commonName)
        self.assertEqual(
            u'name@xn--domain-uro-x77e.com', subject.emailAddress)
        self.assertEqual(u'OU Nam\u20acuro', subject.organizationName)
        self.assertEqual(u'OU Unit\u20acuro', subject.organizationalUnitName)
        self.assertEqual(u'Som\u20acwhere', subject.localityName)
        self.assertEqual(u'Stat\u20ac', subject.stateOrProvinceName)
        self.assertEqual(u'GB', subject.countryName)

    def test_encrypted_key(self):
        """
        When asked it serialized the key with a password.
        """
        options = self.parseArguments([
            self.command_name,
            u'--common-name=domain.com',
            u'--key-size=512',
            u'--key-password=\u20acuro',
            ])

        result = generate_csr(options)

        # We decrypt the key and compare the unencrypted serialization.
        key = crypto.load_privatekey(
            crypto.FILETYPE_PEM,
            result['key_pem'],
            u'\u20acuro'.encode('utf-8'))
        self.assertEqual(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, key),
            crypto.dump_privatekey(crypto.FILETYPE_PEM, result['key']),
            )

    def test_dsa_key(self):
        """
        It can also generate key as DSA.
        """
        options = self.parseArguments([
            self.command_name,
            u'--common-name=domain.com',
            u'--key-size=512',
            u'--key-type=dsa',
            ])

        result = generate_csr(options)

        self.assertEqual(crypto.TYPE_DSA, result['key'].type())


class Test_generate_and_store_csr(CommandLineTestBase):
    """
    Unit tests for generate_and_store_csr.
    """

    def test_key_exists(self):
        """
        Raise an exception when server key already exists.
        """
        self.test_segments = mk.fs.createFileInTemp()
        path = mk.fs.getRealPathFromSegments(self.test_segments)
        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            '--key-file', path,
            ])

        with self.assertRaises(KeyCertException) as context:
            generate_and_store_csr(options)

        self.assertEqual('Key file already exists.', context.exception.message)

    def test_key_and_csr(self):
        """
        Will write the key an csr on local filesystem.
        """
        key_path, self.test_segments = mk.fs.makePathInTemp()
        csr_segments = self.test_segments[:]
        csr_segments[-1] = u'%s.csr' % csr_segments[-1]
        self.addCleanup(mk.fs.deleteFile, csr_segments)

        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            '--key-file', key_path,
            '--key-size=512',
            ])

        generate_and_store_csr(options)

        key_content = mk.fs.getFileContent(self.test_segments)
        key = crypto.load_privatekey(
            crypto.FILETYPE_PEM, key_content)
        self.assertEqual(512, key.bits())
        csr_content = mk.fs.getFileContent(csr_segments)
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_content)
        self.assertEqual(u'domain.com', csr.get_subject().CN)
