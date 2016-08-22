# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
SSL keys and certificates.
"""
from socket import gethostname
import os

from OpenSSL import crypto

from chevah.keycert import _path
from chevah.keycert.exceptions import KeyCertException

_DEFAULT_SSL_KEY_CYPHER = b'aes-256-cbc'


def generate_ssl_self_signed_certificate():
    """
    Generate a self signed SSL certificate.

    Returns a tuple of (certificate_pem, key_pem)
    """
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "UN"
    cert.get_subject().ST = "Oceania"
    cert.get_subject().L = "Pitcairn Islands"
    cert.get_subject().O = "ACME Inc."
    cert.get_subject().OU = "Henderson"
    cert.get_subject().CN = gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')

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

    key = crypto.PKey()
    key.generate_key(key_type, options.key_size)

    csr.add_extensions(extensions)
    csr.set_pubkey(key)

    try:
        csr.sign(key, 'sha256')
    except ValueError:  # pragma: no cover
        # If SHA256 is not supported, fallback to sha1.
        csr.sign(key, 'sha1')

    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
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
