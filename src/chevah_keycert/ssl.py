# Copyright (c) 2015 Adi Roiban.
# See LICENSE for details.
"""
SSL keys and certificates.
"""
import os
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from random import randint

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from OpenSSL import crypto

from chevah_keycert.exceptions import KeyCertException

_DEFAULT_SSL_KEY_CYPHER = "aes-256-cbc"
_SUPPORTED_SIGN_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]

# See https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
_KEY_USAGE_STANDARD = {
    "digital-signature": b"digitalSignature",
    "non-repudiation": b"nonRepudiation",
    "key-encipherment": b"keyEncipherment",
    "data-encipherment": b"dataEncipherment",
    "key-agreement": b"keyAgreement",
    "key-cert-sign": b"keyCertSign",
    "crl-sign": b"cRLSign",
    "encipher-only": b"encipherOnly",
    "decipher-only": b"decipherOnly",
}
_KEY_USAGE_EXTENDED = {
    "server-authentication": x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
    "client-authentication": x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
    "code-signing": x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
    "email-protection": x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
}


def _generate_self_csr_parser(sub_command, default_key_size):
    """
    Add share configuration options for CSR and self-signed generation.
    """
    sub_command.add_argument(
        "--common-name",
        help="Common name associated with the certificate.",
        required=True,
    )

    sub_command.add_argument(
        "--key-size",
        type=int,
        metavar="SIZE",
        default=default_key_size,
        help="Size of the generate RSA private key. Default %(default)s",
    )

    sub_command.add_argument(
        "--sign-algorithm",
        default="sha256",
        metavar="STRING",
        help="Signature algorithm: sha1, sha256, sha512. Default: sha256.",
    )

    sub_command.add_argument(
        "--key-usage",
        default="",
        help=(
            "Comma-separated key usage. "
            "The following key usage extensions are supported: %s. "
            "To mark usage as critical, prefix the values with `critical,`. "
            'For example: "critical,key-agreement,digital-signature".'
        )
        % (
            ", ".join(
                list(_KEY_USAGE_STANDARD.keys()) + list(_KEY_USAGE_EXTENDED.keys())
            )
        ),
    )

    sub_command.add_argument(
        "--constraints",
        default="",
        help=(
            "Comma-separated basic constraints. "
            "To mark constraints as critical, prefix the values with "
            "`critical,`. "
            'For example: "critical,CA:TRUE,pathlen:0".'
        ),
    )

    sub_command.add_argument(
        "--email",
        help="Email address.",
    )
    sub_command.add_argument(
        "--alternative-name",
        help=(
            "Optional list of alternative names. "
            'Use "DNS:your.domain.tld" for domain names. '
            'Use "IP:1.2.3.4" for IP addresses. '
            'Example: "DNS:top.com,DNS:www.top.com,IP:11.0.21.12".'
        ),
    )
    sub_command.add_argument(
        "--organization",
        help="Organization.",
    )
    sub_command.add_argument(
        "--organization-unit",
        help="Organization unit.",
    )
    sub_command.add_argument(
        "--locality",
        help="Full name of the locality.",
    )
    sub_command.add_argument(
        "--state",
        help=("Full name of the state/county/region/province."),
    )
    sub_command.add_argument(
        "--country",
        help=("Two-letter country code."),
    )


def generate_csr_parser(subparsers, name, default_key_size=2048):
    """
    Create an argparse sub-command for generating CSR options with
    `name` attached to `subparsers`.
    """
    sub_command = subparsers.add_parser(
        name,
        help=(
            "Create an SSL private key and an associated certificate "
            "signing request."
        ),
    )

    sub_command.add_argument(
        "--key",
        metavar="FILE",
        default=None,
        help=(
            "Sign the CSR using this private key. "
            "Private key loaded as PEM PKCS#8 format. "
        ),
    )
    sub_command.add_argument(
        "--key-file",
        metavar="FILE",
        default="server.key",
        help=(
            "Store the keys/CSR pair in FILE and FILE.csr. "
            "Private key stored using PEM PKCS#8 format. "
            "CSR file stored in PEM x509 format. "
            "Default names: server.key and server.csr."
        ),
    )

    sub_command.add_argument(
        "--key-password",
        metavar="PASSPHRASE",
        help=(
            "Password used to encrypt the generated key. "
            "Default no encryption. Encrypted with %s." % (_DEFAULT_SSL_KEY_CYPHER,)
        ),
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
            "Create an SSL private key " "and an associated self-signed certificate."
        ),
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
    except (crypto.Error, ValueError, TypeError) as error:
        if isinstance(error, crypto.Error):
            try:
                message = error[0][0][2].decode("utf-8", errors="replace")
            except IndexError:  # pragma: no cover
                message = "no error details."
        else:
            message = str(error)
        raise KeyCertException(message)


def _parse_email(options):
    """
    Return a normalized email value or None.
    """
    email = getattr(options, "email", "")
    if not email:
        return None

    try:
        address, domain = email.split("@", 1)
    except ValueError:
        raise KeyCertException("Invalid email address.")

    return "%s@%s" % (
        address,
        domain.encode("idna").decode("ascii"),
    )


def _build_subject(options):
    """
    Build and return the x509.Name for CSR/certificate.
    """
    common_name = options.common_name
    country = getattr(options, "country", "")
    state = getattr(options, "state", "")
    locality = getattr(options, "locality", "")
    organization = getattr(options, "organization", "")
    organization_unit = getattr(options, "organization_unit", "")
    email = _parse_email(options)

    if country:
        if len(country) != 2:
            raise KeyCertException("Invalid country code.")

    attributes = [
        x509.NameAttribute(
            x509.oid.NameOID.COMMON_NAME, common_name.encode("idna").decode()
        ),
    ]

    if country:
        attributes.append(x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, country))

    if state:
        attributes.append(
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, state)
        )

    if locality:
        attributes.append(x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, locality))

    if organization:
        attributes.append(
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, organization)
        )

    if organization_unit:
        attributes.append(
            x509.NameAttribute(
                x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit
            )
        )

    if email:
        attributes.append(
            x509.NameAttribute(
                x509.oid.NameOID.EMAIL_ADDRESS,
                email,
            )
        )

    return x509.Name(attributes)


def _parse_constraints(constraints):
    """
    Parse basic constraints option.
    """
    ca = None
    pathlen = None
    for part in constraints.split(","):
        item = part.strip()
        if not item:
            continue
        if ":" not in item:
            continue
        key, value = item.split(":", 1)
        name = key.strip().lower()
        raw = value.strip()
        if name == "ca":
            ca = raw.upper() == "TRUE"
        elif name == "pathlen":
            pathlen = int(raw)

    if ca is None:
        raise KeyCertException("Invalid constraints value.")
    if not ca and pathlen is not None:
        raise KeyCertException("Invalid constraints value.")
    return x509.BasicConstraints(ca=ca, path_length=pathlen)


def _parse_alternative_name(alternative_name):
    """
    Build a SubjectAlternativeName extension from text input.
    """
    names = []
    for entry in alternative_name.split(","):
        item = entry.strip()
        if not item:
            continue
        kind, value = item.split(":", 1)
        key = kind.upper().strip()
        target = value.strip()
        if key == "DNS":
            names.append(x509.DNSName(target.encode("idna").decode("ascii")))
        elif key == "IP":
            names.append(x509.IPAddress(ip_address(target)))
        else:
            raise KeyCertException("Invalid alternative name.")
    return x509.SubjectAlternativeName(names)


def _build_extensions(options):
    """
    Build x509 extensions from command options.
    """
    constraints = getattr(options, "constraints", "")
    key_usage = getattr(options, "key_usage", "").lower()
    alternative_name = getattr(options, "alternative_name", "")

    critical_constraints = False
    critical_usage = False
    standard_usage = set()
    extended_usage = []
    extensions = []

    if constraints.lower().startswith("critical"):
        critical_constraints = True
        constraints = constraints[8:].strip(",").strip()

    if key_usage.startswith("critical"):
        critical_usage = True
        key_usage = key_usage[8:]

    for usage in key_usage.split(","):
        usage = usage.strip()
        if not usage:
            continue
        if usage in _KEY_USAGE_STANDARD:
            standard_usage.add(usage)
        if usage in _KEY_USAGE_EXTENDED:
            extended_usage.append(_KEY_USAGE_EXTENDED[usage])

    if constraints:
        extensions.append(
            (
                _parse_constraints(constraints),
                critical_constraints,
            )
        )

    if standard_usage:
        key_agreement = "key-agreement" in standard_usage
        extensions.append(
            (
                x509.KeyUsage(
                    digital_signature="digital-signature" in standard_usage,
                    content_commitment="non-repudiation" in standard_usage,
                    key_encipherment="key-encipherment" in standard_usage,
                    data_encipherment="data-encipherment" in standard_usage,
                    key_agreement=key_agreement,
                    key_cert_sign="key-cert-sign" in standard_usage,
                    crl_sign="crl-sign" in standard_usage,
                    encipher_only=(
                        "encipher-only" in standard_usage if key_agreement else None
                    ),
                    decipher_only=(
                        "decipher-only" in standard_usage if key_agreement else None
                    ),
                ),
                critical_usage,
            )
        )

    if extended_usage:
        extensions.append(
            (
                x509.ExtendedKeyUsage(extended_usage),
                critical_usage,
            )
        )

    # Alternate name is optional.
    if alternative_name:
        extensions.append(
            (
                _parse_alternative_name(alternative_name),
                False,
            )
        )
    return extensions


def _generate_csr(options):
    """
    Helper to catch all crypto errors and reduce indentation.
    """
    key_size = getattr(options, "key_size", 2048)

    if key_size < 512:
        raise KeyCertException("Key size must be greater or equal to 512.")

    subject = _build_subject(options)
    extensions = _build_extensions(options)

    key_pem = None
    private_key = options.key
    if private_key:
        if os.path.exists(private_key):
            with open(private_key, "rb") as stream:
                private_key = stream.read()

        key_pem = private_key
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
    else:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, key_size)

    crypto_key = key.to_cryptography_key()
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    for extension, critical in extensions:
        csr_builder = csr_builder.add_extension(extension, critical)
    csr = csr_builder.sign(
        private_key=crypto_key,
        algorithm=_get_sign_hash(options),
    )
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

    if not key_pem:
        if options.key_password:
            cipher = _DEFAULT_SSL_KEY_CYPHER
            key_pem = crypto.dump_privatekey(
                crypto.FILETYPE_PEM,
                key,
                cipher,
                options.key_password.encode("utf-8"),
            )
        else:
            key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    return {
        "csr_pem": csr_pem,
        "key_pem": key_pem,
        "csr": crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_pem),
        "key": key,
    }


def _get_sign_hash(options):
    """
    Return hashing algorithm object for signing.
    """
    sign_algorithm = getattr(options, "sign_algorithm", "sha256")
    sign_algorithms = {
        "md5": hashes.MD5,
        "sha1": hashes.SHA1,
        "sha256": hashes.SHA256,
        "sha512": hashes.SHA512,
    }

    if sign_algorithm not in sign_algorithms:
        raise KeyCertException(
            "Invalid signing algorithm. Supported values: %s."
            % (", ".join(_SUPPORTED_SIGN_ALGORITHMS))
        )

    return sign_algorithms[sign_algorithm]()


def generate_ssl_self_signed_certificate(options):
    """
    Generate a self signed SSL certificate.

    Returns a tuple of (certificate_pem, key_pem)
    """
    key_size = getattr(options, "key_size", 2048)

    serial = randint(0, 1000000000000)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, key_size)
    generated_key = key.to_cryptography_key()
    subject = _build_subject(options)
    issuer = subject
    now = datetime.now(timezone.utc)

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(generated_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
    )
    for extension, critical in _build_extensions(options):
        cert_builder = cert_builder.add_extension(extension, critical)

    cert = cert_builder.sign(
        private_key=generated_key,
        algorithm=_get_sign_hash(options),
    )
    certificate_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    return (certificate_pem.decode("utf-8"), key_pem.decode("utf-8"))


def generate_and_store_csr(options):
    """
    Generate a key/csr and try to store it on disk.

    Raise KeyCertException when failing to create the key or csr.
    """
    name, _ = os.path.splitext(options.key_file)
    csr_name = "%s.csr" % name

    if os.path.exists(options.key_file):
        raise KeyCertException("Key file already exists.")

    result = generate_csr(options)

    try:
        with open(options.key_file, "wb") as store_file:
            store_file.write(result["key_pem"])

        with open(csr_name, "wb") as store_file:
            store_file.write(result["csr_pem"])
    except Exception as error:
        raise KeyCertException(str(error))
