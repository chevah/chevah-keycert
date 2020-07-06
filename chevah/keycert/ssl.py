# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
SSL keys and certificates.
"""
import os
from random import randint

from OpenSSL import crypto

from chevah.keycert import _path
from chevah.keycert.exceptions import KeyCertException

_DEFAULT_SSL_KEY_CYPHER = b'aes-256-cbc'

# See https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
_KEY_USAGE_STANDARD = {
    'digital-signature': b'digitalSignature',
    'non-repudiation': b'nonRepudiation',
    'key-encipherment': b'keyEncipherment',
    'data-encipherment': b'dataEncipherment',
    'key-agreement': b'keyAgreement',
    'key-cert-sign': b'keyCertSign',
    'crl-sign': b'cRLSign',
    'encipher-only': b'encipherOnly',
    'decipher-only': b'decipherOnly',
    }
_KEY_USAGE_EXTENDED = {
    'server-authentication': b'serverAuth',
    'client-authentication': b'clientAuth',
    'code-signing': b'codeSigning',
    'email-protection': b'emailProtection',
    }


def generate_ssl_self_signed_certificate(options):
    """
    Generate a self signed SSL certificate.

    Returns a tuple of (certificate_pem, key_pem)
    """
    key_size = options.key_size
    sign_algorithm = options.sign_algorithm
    key_usage = options.key_usage.lower()

    serial = randint(0, 1000000000000)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, key_size)

    # create a self-signed cert
    cert = crypto.X509()

    cert.get_subject().CN = options.common_name.encode('idna')

    if options.country:
        cert.get_subject().C = options.country.encode('ascii')

    if options.state:
        cert.get_subject().ST = options.state.encode('ascii')

    if options.locality:
        cert.get_subject().L = options.locality.encode('ascii')

    if options.organization:
        cert.get_subject().O = options.organization.encode('ascii')

    if options.organization_unit:
        cert.get_subject().OU = options.organization_unit.encode('ascii')

    critical_usage = False
    standard_usage = []
    extended_usage = []

    if key_usage.startswith('critical:'):
        critical_usage = True
        key_usage = key_usage[9:]
    for usage in key_usage.split(','):
        usage = usage.strip()
        if not usage:
            continue
        if usage in _KEY_USAGE_STANDARD:
            standard_usage.append(_KEY_USAGE_STANDARD[usage])
        if usage in _KEY_USAGE_EXTENDED:
            extended_usage.append(_KEY_USAGE_EXTENDED[usage])

    extensions = [
        crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),
        ]
    if standard_usage:
        extensions.append(crypto.X509Extension(
            b'keyUsage',
            critical_usage,
            b','.join(standard_usage),
            ))

    if extended_usage:
        extensions.append(crypto.X509Extension(
            b'extendedKeyUsage',
            critical_usage,
            b','.join(extended_usage),
            ))

    # Alternate name is optional.
    if options.alternative_name:
        extensions.append(crypto.X509Extension(
            b'subjectAltName',
            False,
            options.alternative_name.encode('idna')))
    cert.add_extensions(extensions)

    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, sign_algorithm)

    certificate_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    return (certificate_pem, key_pem)


def generate_csr_parser(subparsers, name, default_key_size=2048):
    """
    Create an argparse sub-command for generating CSR options with
    `name` attached to `subparsers`.
    """
    sub_command = subparsers.add_parser(
        name,
        help=(
            'Create a SSL private key and associated certificate '
            'signing request.'),
        )
    sub_command.add_argument(
        '--common-name',
        help='Common name associated with the generated CSR.',
        required=True,
        )
    sub_command.add_argument(
        '--key',
        metavar="FILE",
        default=None,
        help=(
            'Sign the CSR using this private key. '
            'Private key loaded as PEM PKCS#8 format. '
            ),
        )
    sub_command.add_argument(
        '--key-file',
        metavar="FILE",
        default='server.key',
        help=(
            'Store the keys/csr pair in FILE and FILE.csr. '
            'Private key stored using PEM PKCS#8 format. '
            'CSR file stored in PEM x509 format. '
            'Default server.key and server.csr.'),
        )
    sub_command.add_argument(
        '--key-size',
        type=int, metavar="SIZE", default=default_key_size,
        help='Size of the generate RSA private key. Default %(default)s',
        )

    sub_command.add_argument(
        '--key-password',
        metavar="PASSPHRASE",
        help=(
            'Password used to encrypt the generated key. '
            'Default no encryption. Encrypted with %s.' % (
                _DEFAULT_SSL_KEY_CYPHER,)),
        )
    sub_command.add_argument(
        '--email',
        help='Email address used by the requested command.',
        )
    sub_command.add_argument(
        '--alternative-name',
        help='Optional list of alternative name of the generated CSR.',
        )
    sub_command.add_argument(
        '--organization',
        help='Organization associated with the generated CSR.',
        )
    sub_command.add_argument(
        '--organization-unit',
        help='Organization unit associated with the generated CSR.',
        )
    sub_command.add_argument(
        '--locality',
        help='Full name of the locality associated with the generated CSR.',
        )
    sub_command.add_argument(
        '--state',
        help=(
            'Full name of the state/county/region/province associated with the'
            ' generated CSR.'),
        )
    sub_command.add_argument(
        '--country',
        help=(
            'Two letter code of the country associated with the '
            'generated CSR.'),
        )
    return sub_command


def generate_self_signed_parser(subparsers, name, default_key_size=2048):
    """
    Create an argparse sub-command for generating self signed options with
    `name` attached to `subparsers`.
    """
    sub_command = subparsers.add_parser(
        name,
        help=(
            'Create a SSL private key '
            'and associated self signed certificate.'),
        )
    sub_command.add_argument(
        '--common-name',
        help='Common name associated with the certificate.',
        required=True,
        )

    sub_command.add_argument(
        '--key-size',
        type=int, metavar="SIZE", default=default_key_size,
        help='Size of the generate RSA private key. Default %(default)s',
        )

    sub_command.add_argument(
        '--sign-algorithm',
        default='sha256',
        metavar='STRING',
        help='Signature algorithm: sha1, sha256, sha512. Default: sha256.'
        )

    sub_command.add_argument(
        '--key-usage',
        default='',
        help=(
            'Comma separated key usage. '
            'The following usage extension are supported: %s. '
            'To mark usage as critical, prefix the values with `critical:`. '
            'For example: "critical:key-agreement,digital-signature".'
            ) % (', '.join(
                _KEY_USAGE_STANDARD.keys() + _KEY_USAGE_EXTENDED.keys())),
        )

    sub_command.add_argument(
        '--email',
        help='Email address.',
        )
    sub_command.add_argument(
        '--alternative-name',
        help=(
            'Optional list of alternative names. '
            'Use "DNS:your.domain.tld" for domain names. '
            'Use "IP:1.2.3.4" for IP addresses. '
            'Example: "DNS:top.com,DNS:www.top.com,IP:11.0.21.12".'
            )
        )
    sub_command.add_argument(
        '--organization',
        help='Organization.',
        )
    sub_command.add_argument(
        '--organization-unit',
        help='Organization unit.',
        )
    sub_command.add_argument(
        '--locality',
        help='Full name of the locality.',
        )
    sub_command.add_argument(
        '--state',
        help=(
            'Full name of the state/county/region/province.'),
        )
    sub_command.add_argument(
        '--country',
        help=(
            'Two letter code of the country.'),
        )
    return sub_command


def generate_csr(options):
    """
    Generate a new SSL key and the associated SSL cert signing.

    Returns a tuple of (csr_pem, key_pem)
    Raise KeyCertException on failure.
    """
    try:
        return _generate_csr(options)
    except crypto.Error as error:
        try:
            message = error[0][0][2]
        except IndexError:  # pragma: no cover
            message = 'no error details.'
        raise KeyCertException(message)


def _generate_csr(options):
    """
    Helper to catch all crypto errors and reduce indentation.
    """
    if options.key_size < 512:
        raise KeyCertException('Key size must be greater or equal to 512.')

    key_type = crypto.TYPE_RSA

    csr = crypto.X509Req()

    # RFC 2459 defines it as optional, and pyopenssl set it to `0` anyway.
    # But we got reports that Windows 2003 and Windows 2008 Servers
    # can not parse CSR generated using this tool, so here we are.
    csr.set_version(0)

    subject = csr.get_subject()

    if options.common_name:
        subject.commonName = options.common_name.encode('idna')

    if options.organization:
        subject.organizationName = options.organization

    if options.organization_unit:
        subject.organizationalUnitName = options.organization_unit

    if options.locality:
        subject.localityName = options.locality

    if options.state:
        subject.stateOrProvinceName = options.state

    if options.country:
        subject.countryName = options.country

    if options.email:
        address, domain = options.email.split('@', 1)
        subject.emailAddress = u'%s@%s' % (address, domain.encode('idna'))

    # We create a CSR which can not be used as a CA, but designated to be
    # used as server certificate.
    keyusage = (
        b'digitalSignature, nonRepudiation, keyEncipherment, keyAgreement')
    extensions = [
        crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),
        crypto.X509Extension(b'keyUsage', False, keyusage),
        crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth'),
        ]

    # Alternate name is optional.
    if options.alternative_name:
        extensions.append(crypto.X509Extension(
            b'subjectAltName',
            False,
            options.alternative_name.encode('idna')))

    csr.add_extensions(extensions)

    key_pem = None
    private_key = options.key
    if private_key:
        if os.path.exists(_path(private_key)):
            with open(_path(private_key), 'rb') as stream:
                private_key = stream.read()

        key_pem = private_key
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
    else:
        # Generate new Key.
        key = crypto.PKey()
        key.generate_key(key_type, options.key_size)

    csr.set_pubkey(key)

    try:
        csr.sign(key, 'sha256')
    except ValueError:  # pragma: no cover
        # If SHA256 is not supported, fallback to sha1.
        csr.sign(key, 'sha1')

    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)

    if not key_pem:
        if options.key_password:
            key_pem = crypto.dump_privatekey(
                crypto.FILETYPE_PEM, key,
                _DEFAULT_SSL_KEY_CYPHER, options.key_password.encode('utf-8'))
        else:
            key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    return {
        'csr_pem': csr_pem,
        'key_pem': key_pem,
        'csr': csr,
        'key': key,
        }


def generate_and_store_csr(options, encoding='utf-8'):
    """
    Generate a key/csr and try to store it on disk.

    Raise KeyCertException when failing to create the key or csr.
    """
    name, _ = os.path.splitext(options.key_file)
    csr_name = u'%s.csr' % name

    if os.path.exists(_path(options.key_file, encoding)):
        raise KeyCertException('Key file already exists.')

    result = generate_csr(options)

    try:
        with open(_path(options.key_file, encoding), 'wb') as store_file:
            store_file.write(result['key_pem'])

        with open(_path(csr_name, encoding), 'wb') as store_file:
            store_file.write(result['csr_pem'])
    except Exception, error:
        raise KeyCertException(str(error))
