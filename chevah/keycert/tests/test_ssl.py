# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
Test for SSL keys/cert management.
"""
from argparse import ArgumentParser

from bunch import Bunch
from chevah.compat.testing import mk, ChevahTestCase
from OpenSSL import crypto

from chevah.keycert.exceptions import KeyCertException
from chevah.keycert.ssl import (
    generate_and_store_csr,
    generate_csr,
    generate_csr_parser,
    generate_self_signed_parser,
    generate_ssl_self_signed_certificate,
    )
from chevah.keycert.tests.helpers import CommandLineMixin

RSA_PRIVATE = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTKAPkPAWzlu5BRHcmA
u0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk+X6Lc4+lAfp1YxCR
9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcjRToF6/jpLwIDAQAB
AoGACB5cQDvxmBdgYVpuy43DduabTmR71HFaNFl+nE5vwFxUqX0qFOQpG0E2Cv56
zesPzT1JWBiqffSir4iSjH/lnskZnM9J1xfpnoJ5HTzcGHaBYVFEEXS6fOsyWT15
oY7Kb6rRBTnWV0Ins/05Hhp38r/RR/O4poB+3NwQJDl/6gECQQDoAnRdC+5SyjrZ
1JQUWUkapiYHIhFq6kWtGm3kWJn0IxCBtFhGvqIWJwZIAjf6tTKMUk6bjG9p7Jpe
tXUsTiDBAkEAy5EDU2F42Xm6tvQzM8bAgq7d2/x2iHRuOkDUb1bK3YwByTihl9BL
qvdRhRxpl21EcqWpB/RzAFbGa+60G/iV7wJABSz415KKkII+admaLBIJ1XRbaNFT
viTXxRLP3MY1OQMHPT1+sqVSDFh2hWi3QvqD1CmJ42JwodZLY018/a4IgQJAOsCg
yBjyyznB9PnoKUJs34rex5ZHE70e7zs01Omk5Wp6PXxVzz40CKUW5yc7JpRH1BsR
/RTFeEyTOiWL4CLQCwJAf4BF9eVLxRQ9A4Mm9Ikt4lF8ii6na4nxdtEzP8p2LP9t
LqHYUobNanxB+7Msi4f3gYyuKdOGnWHqD2U4HcLdMQ==
-----END RSA PRIVATE KEY-----
"""


class CommandLineTestBase(ChevahTestCase, CommandLineMixin):
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
        generate_self_signed_parser(subparser, 'self-gen')


class Test_generate_ssl_self_signed_certificate(CommandLineTestBase):
    """
    Unit tests for generate_ssl_self_signed_certificate.
    """

    def test_generate(self):
        """
        Will generate the key and self signed certificate for current
        hostname.
        """
        options = self.parseArguments([
            'self-gen',
            '--common-name', 'domain.com',
            '--key-size=1024',
            '--alternative-name=DNS:ex.com,IP:1.2.3.4',
            '--constraints=critical,CA:TRUE',
            '--key-usage=server-authentication,crl-sign',
            '--sign-algorithm=sha512',
            '--email=dev@chevah.com',
            '--state=MS',
            '--locality=Cluj',
            '--organization=Chevah Team',
            '--organization-unit=DevTeam',
            '--country=UN',
            ])

        cert_pem, key_pem = generate_ssl_self_signed_certificate(options)

        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        self.assertEqual(1024, key.bits())
        self.assertEqual(crypto.TYPE_RSA, key.type())
        self.assertEqual(u'domain.com', cert.get_subject().CN)

        self.assertEqual(u'dev@chevah.com', cert.get_subject().emailAddress)

        self.assertEqual(u'MS', cert.get_subject().ST)
        self.assertEqual(u'Cluj', cert.get_subject().L)
        self.assertEqual(u'Chevah Team', cert.get_subject().O)
        self.assertEqual(u'DevTeam', cert.get_subject().OU)
        self.assertEqual(u'UN', cert.get_subject().C)

        self.assertNotEqual(0, cert.get_serial_number())
        issuer = cert.get_issuer()
        self.assertEqual(cert.subject_name_hash(), issuer.hash())

        constraints = cert.get_extension(0)
        self.assertEqual('basicConstraints', constraints.get_short_name())
        self.assertTrue(constraints.get_critical())
        self.assertEqual(b'0\x03\x01\x01\xff', constraints.get_data())

        key_usage = cert.get_extension(1)
        self.assertEqual('keyUsage', key_usage.get_short_name())
        self.assertFalse(key_usage.get_critical())

        extended_usage = cert.get_extension(2)
        self.assertEqual('extendedKeyUsage', extended_usage.get_short_name())
        self.assertFalse(extended_usage.get_critical())

        alt_name = cert.get_extension(3)
        self.assertEqual('subjectAltName', alt_name.get_short_name())
        self.assertFalse(alt_name.get_critical())
        self.assertEqual(
            b'0\x0e\x82\x06ex.com\x87\x04\x01\x02\x03\x04',
            alt_name.get_data())

    def test_generate_basic_options(self):
        """
        Can generate using just common name as the options.
        """
        options = Bunch(common_name='test')

        cert_pem, key_pem = generate_ssl_self_signed_certificate(options)

        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        self.assertEqual(2048, key.bits())
        self.assertEqual(crypto.TYPE_RSA, key.type())
        self.assertEqual(u'test', cert.get_subject().CN)
        self.assertIsNone(cert.get_subject().C)
        self.assertNotEqual(0, cert.get_serial_number())
        issuer = cert.get_issuer()
        self.assertEqual(cert.subject_name_hash(), issuer.hash())
        # No extensions are set.
        self.assertEqual(0, cert.get_extension_count())


class Test_generate_csr_parser(
        ChevahTestCase, CommandLineMixin):
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
        It can be initialized with only a subparser and sub-command name.
        """
        generate_csr_parser(self.subparser, 'key-gen')

        options = self.parseArguments([
            'key-gen',
            '--common-name', 'domain.com',
            ])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key': None,
            'key_file': 'server.key',
            'key_size': 2048,
            'key_password': None,
            'common_name': 'domain.com',
            'alternative_name': None,
            'email': None,
            'organization': None,
            'organization_unit': None,
            'locality': None,
            'state': None,
            'country': None,
            'constraints': '',
            'key_usage': '',
            'sign_algorithm': 'sha256',
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
            '--key-password', u'valu\u20ac',
            '--alternative-name', 'DNS:www.domain.com,IP:127.0.0.1',
            '--email', 'admin@domain.com',
            '--organization', 'OU Name',
            '--organization-unit=OU Unit',
            '--locality=somewhere',
            '--state=without',
            '--country=GB',
            '--constraints=critical,CA:FALSE',
            '--key-usage=crl-sign',
            '--sign-algorithm=sha1',
            ])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key': None,
            'key_file': 'my_server.pem',
            'key_size': 1024,
            'key_password': u'valu\u20ac',
            'common_name': 'sub.domain.com',
            'alternative_name': 'DNS:www.domain.com,IP:127.0.0.1',
            'email': 'admin@domain.com',
            'organization': 'OU Name',
            'organization_unit': 'OU Unit',
            'locality': 'somewhere',
            'state': 'without',
            'country': 'GB',
            'constraints': 'critical,CA:FALSE',
            'key_usage': 'crl-sign',
            'sign_algorithm': 'sha1',

            }, options)

    def test_default_overwrite(self):
        """
        You can change default values.
        """
        generate_csr_parser(
            self.subparser, 'key-gen',
            default_key_size=1024,
            )

        options = self.parseArguments([
            'key-gen',
            '--common-name', 'domain.com',
            ])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key': None,
            'key_file': 'server.key',
            'key_size': 1024,
            'key_password': None,
            'common_name': 'domain.com',
            'alternative_name': None,
            'email': None,
            'organization': None,
            'organization_unit': None,
            'locality': None,
            'state': None,
            'country': None,
            'constraints': '',
            'key_usage': '',
            'sign_algorithm': 'sha256',
            }, options)


class Test_generate_csr(CommandLineTestBase):
    """
    Unit tests for generate_csr.
    """

    def test_bad_size(self):
        """
        Raise an exception when failing to generate the key.
        """
        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            '--key-size=12',
            ])

        with self.assertRaises(KeyCertException) as context:
            generate_csr(options)

        self.assertEqual(
            'Key size must be greater or equal to 512.',
            context.exception.message)

    def test_bad_country_long(self):
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

    def test_bad_country_short(self):
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
        self.assertEqual(0, result['csr'].get_version())

    def test_gen_unicode(self):
        """
        Domains are encoded using IDNA and names using Unicode.
        """
        options = self.parseArguments([
            self.command_name,
            u'--common-name=domain-\u20acuro.com',
            u'--key-size=512',
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
        When asked it will serialize the key with a password.
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

    def test_existing_key_string(self):
        """
        It can generate a CSR from an existing private key as text.
        """
        key_pem = RSA_PRIVATE

        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            ])
        options.key = key_pem

        result = generate_csr(options)

        # OpenSSL.crypto.PKey has no equality so we need to compare the
        # serialization.
        self.assertEqual(1024L, result['key'].bits())
        self.assertEqual(crypto.TYPE_RSA, result['key'].type())
        self.assertEqual(key_pem, result['key_pem'])
        # For CSR we can not get extensions so we only check the subject.
        csr = crypto.dump_certificate_request(
            crypto.FILETYPE_PEM, result['csr'])
        self.assertEqual(csr, result['csr_pem'])
        subject = result['csr'].get_subject()
        self.assertEqual(u'domain.com', subject.commonName)

    def test_existing_key_path(self):
        """
        It can generate a CSR from an existing private key file.
        """
        key_pem = RSA_PRIVATE
        key_path, _ = self.tempFile(content=key_pem)

        options = self.parseArguments([
            self.command_name,
            '--key', key_path,
            '--common-name=domain.com',
            ])

        result = generate_csr(options)

        # OpenSSL.crypto.PKey has no equality so we need to compare the
        # serialization.
        self.assertEqual(1024L, result['key'].bits())
        self.assertEqual(crypto.TYPE_RSA, result['key'].type())
        self.assertEqual(key_pem, result['key_pem'])
        # For CSR we can not get extensions so we only check the subject.
        csr = crypto.dump_certificate_request(
            crypto.FILETYPE_PEM, result['csr'])
        self.assertEqual(csr, result['csr_pem'])
        subject = result['csr'].get_subject()
        self.assertEqual(u'domain.com', subject.commonName)


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

    def test_store_error(self):
        """
        Raise an exception when failing to write the file.
        """
        options = self.parseArguments([
            self.command_name,
            '--common-name=domain.com',
            '--key-file', 'no-such/parent/key.file',
            '--key-size=512',
            ])

        with self.assertRaises(KeyCertException) as context:
            generate_and_store_csr(options)

        self.assertEqual(
            "[Errno 2] No such file or directory: 'no-such/parent/key.file'",
            context.exception.message)
