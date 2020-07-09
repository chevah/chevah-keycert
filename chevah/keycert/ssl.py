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


def _generate_self_csr_parser(sub_command, default_key_size):
    """
    Add share configuration options for CSR and self-signed generation.
    """
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
            'Comma-separated key usage. '
            'The following key usage extensions are supported: %s. '
            'To mark usage as critical, prefix the values with `critical,`. '
            'For example: "critical,key-agreement,digital-signature".'
            ) % (', '.join(
                _KEY_USAGE_STANDARD.keys() + _KEY_USAGE_EXTENDED.keys())),
        )

    sub_command.add_argument(
        '--constraints',
        default='',
        help=(
            'Comma-separated basic constraints. '
            'To mark constraints as critical, prefix the values with '
            '`critical,`. '
            'For example: "critical,CA:TRUE,pathlen:0".'
            ),
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
            'Two-letter country code.'),
        )


def generate_csr_parser(subparsers, name, default_key_size=2048):
    """
    Create an argparse sub-command for generating CSR options with
    `name` attached to `subparsers`.
    """
    sub_command = subparsers.add_parser(
        name,
        help=(
            'Create an SSL private key and an associated certificate '
            'signing request.'),
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
            'Store the keys/CSR pair in FILE and FILE.csr. '
            'Private key stored using PEM PKCS#8 format. '
            'CSR file stored in PEM x509 format. '
            'Default names: server.key and server.csr.'),
        )

    sub_command.add_argument(
        '--key-password',
        metavar="PASSPHRASE",
        help=(
            'Password used to encrypt the generated key. '
            'Default no encryption. Encrypted with %s.' % (
                _DEFAULT_SSL_KEY_CYPHER,)),
        )
    _generate_self_csr_parser(sub_command, default_key_size)

    return sub_command


def generate_self_signed_parser(subparsers, name, default_key_size=2048):
    """
    Create an argparse sub-command for generating self signed options with
    `name` attached to `subparsers`.
    """
    sub_command = subparsers.add_parser(
        name,
        help=(
            'Create an SSL private key '
            'and an associated self-signed certificate.'),
        )
    _generate_self_csr_parser(sub_command, default_key_size)
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


def _set_subject_and_extensions(target, options):
    """
    Set the subject and option for `target` CRS or certificate.
    """
    common_name = options.common_name
    constraints = getattr(options, 'constraints', '')
    key_usage = getattr(options, 'key_usage', '').lower()
    email = getattr(options, 'email', '')
    alternative_name = getattr(options, 'alternative_name', '')
    country = getattr(options, 'country', '')
    state = getattr(options, 'state', '')
    locality = getattr(options, 'locality', '')
    organization = getattr(options, 'organization', '')
    organization_unit = getattr(options, 'organization_unit', '')

    # RFC 2459 defines it as optional, and pyopenssl set it to `0` anyway.
    # But we got reports that Windows 2003 and Windows 2008 Servers
    # can not parse CSR generated using this tool, so here we are.
    target.set_version(0)

    subject = target.get_subject()

    subject.CN = common_name.encode('idna')

    if country:
        subject.C = country

    if state:
        subject.ST = state

    if locality:
        subject.L = locality

    if organization:
        subject.O = organization

    if organization_unit:
        subject.OU = organization_unit

    if email:
        address, domain = options.email.split('@', 1)
        subject.emailAddress = u'%s@%s' % (address, domain.encode('idna'))

    critical_constraints = False
    critical_usage = False
    standard_usage = []
    extended_usage = []
    extensions = []

    if constraints.lower().startswith('critical'):
        critical_constraints = True
        constraints = constraints[8:].strip(',').strip()

    if key_usage.startswith('critical'):
        critical_usage = True
        key_usage = key_usage[8:]

    for usage in key_usage.split(','):
        usage = usage.strip()
        if not usage:
            continue
        if usage in _KEY_USAGE_STANDARD:
            standard_usage.append(_KEY_USAGE_STANDARD[usage])
        if usage in _KEY_USAGE_EXTENDED:
            extended_usage.append(_KEY_USAGE_EXTENDED[usage])

    if constraints:
        extensions.append(crypto.X509Extension(
            b'basicConstraints',
            critical_constraints,
            constraints.encode('ascii'),
            ))

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
    if alternative_name:
        extensions.append(crypto.X509Extension(
            b'subjectAltName',
            False,
            alternative_name.encode('idna')))
    target.add_extensions(extensions)


def _sign_cert_or_csr(target, key, options):
    """
    Sign the certificate or CSR.
    """
    sign_algorithm = getattr(options, 'sign_algorithm', 'sha256')
    target.set_pubkey(key)
    target.sign(key, sign_algorithm)


def _generate_csr(options):
    """
    Helper to catch all crypto errors and reduce indentation.
    """
    key_size = getattr(options, 'key_size', 2048)

    if key_size < 512:
        raise KeyCertException('Key size must be greater or equal to 512.')

    key_type = crypto.TYPE_RSA

    csr = crypto.X509Req()

    _set_subject_and_extensions(csr, options)

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
        key.generate_key(key_type, key_size)

    _sign_cert_or_csr(csr, key, options)

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


def generate_ssl_self_signed_certificate(options):
    """
    Generate a self signed SSL certificate.

    Returns a tuple of (certificate_pem, key_pem)
    """
    key_size = getattr(options, 'key_size', 2048)

    serial = randint(0, 1000000000000)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, key_size)

    cert = crypto.X509()

    _set_subject_and_extensions(cert, options)

    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    cert.set_issuer(cert.get_subject())

    _sign_cert_or_csr(cert, key, options)

    certificate_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    return (certificate_pem, key_pem)


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
