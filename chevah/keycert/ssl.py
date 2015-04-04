# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
SSL keys and certificates.
"""
from socket import gethostname

from OpenSSL import crypto

_DEFAULT_SSL_KEY_CYPHER = b'aes-256-cbc'

from chevah.keycert.exceptions import KeyCertException


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


def generate_ssl_key_certificate_signing_request_subparser(
        subparsers, name, default_key_size=2048, default_key_type='rsa'):
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
        help='Generate a RSA or DSA key of size SIZE. Default %(default)s',
        )
    sub_command.add_argument(
        '--key-type',
        metavar="[rsa|dsa]", default=default_key_type,
        help='Generate a DSA or RSA key. Default %(default)s.',
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
        help='Full name location associated with the generated CSR.',
        )
    sub_command.add_argument(
        '--state',
        help=(
            'Full name of the state/county/region associated with the '
            'generated CSR.'),
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
            message = 'Error: %s' % (error[0][0][2],)
        except IndexError:
            message = 'Error: no error details.'
        raise KeyCertException(message)


def _generate_csr(options):
    """
    Helper to catch all crypto errors and reduce indentation.
    """
    key_type = options.key_type.lower()

    if key_type == 'dsa':
        key_type = crypto.TYPE_DSA
    elif key_type == 'rsa':
        key_type = crypto.TYPE_RSA
    else:
        key_type = 'not-suppored'

    csr = crypto.X509Req()
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
        subject.emailAddress = options.email.encode('idna')

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
    csr.sign(key, 'sha256')

    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    if options.key_password:
        key_pem = crypto.dump_privatekey(
            crypto.FILETYPE_PEM, key,
            _DEFAULT_SSL_KEY_CYPHER, options.key_password.encode('utf-8'))
    else:
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    return {
        'csr_pem': csr_pem,
        'csr_key': key_pem,
        'csr': csr,
        'key': key,
        }


def generate_and_store_csr(options):
    """
    Generate a key/csr and try to store it on disk.
    """
    key_segments = local_filesystem.getSegmentsFromRealPath(options.key_file)
    name, _ = os.path.splitext(key_segments[-1])
    csr_name = u'%s.csr' % name
    csr_segments = key_segments[:-1]
    csr_segments.append(csr_name)

    if local_filesystem.exists(key_segments):
        return (1, 'Key file already exists')

    try:
        csr, key = generate_csr(options)
    except KeyCertException as error:
        return (1, error.message)

    store_file = None
    try:
        store_file = local_filesystem.openFileForWriting(key_segments)
        store_file.write(key)
    finally:
        if store_file:
            store_file.close()
    store_file = None
    try:
        store_file = local_filesystem.openFileForWriting(csr_segments)
        store_file.write(csr)
    finally:
        if store_file:
            store_file.close()
    return (0, 'Key and CSR successfully created.')
