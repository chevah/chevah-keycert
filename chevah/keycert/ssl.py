# Copyright (c) 2011 Adi Roiban.
# See LICENSE for details.
"""
SSL keys and certificates.
"""
from socket import gethostname

from OpenSSL import crypto


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
