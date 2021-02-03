# Copyright (c) 2014 Adi Roiban.
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Handling of RSA, DSA, ECDSA, and Ed25519 keys.
"""

from __future__ import absolute_import, division, unicode_literals

import binascii
import itertools

from hashlib import md5, sha1, sha256
import base64
import hmac
import unicodedata
import struct
import textwrap

import bcrypt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa, ec, ed25519, padding, rsa)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_ssh_public_key)
from cryptography import utils

try:

    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature, decode_dss_signature)
except ImportError:
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_rfc6979_signature as encode_dss_signature,
        decode_rfc6979_signature as decode_dss_signature)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pyasn1.error import PyAsn1Error
from pyasn1.type import univ
from pyasn1.codec.ber import decoder as berDecoder
from pyasn1.codec.ber import encoder as berEncoder

import os
import os.path
from os import urandom
from base64 import encodestring as encodebytes
from base64 import decodestring as decodebytes
from cryptography.utils import int_from_bytes, int_to_bytes
from OpenSSL import crypto

from chevah.keycert import common, sexpy, _path
from chevah.keycert.common import (
    long,
    force_unicode,
    iterbytes,
    izip,
    )
from chevah.keycert.exceptions import (
    BadKeyError,
    EncryptedKeyError,
    KeyCertException,
    )
from constantly import NamedConstant, Names

DEFAULT_PUBLIC_KEY_EXTENSION = u'.pub'
DEFAULT_KEY_SIZE = 2048
DEFAULT_KEY_TYPE = 'rsa'
SSHCOM_MAGIC_NUMBER = int('3f6ff9eb', base=16)
PUTTY_HMAC_KEY = 'putty-private-key-file-mac-key'
ID_SHA1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'

# Curve lookup table
_curveTable = {
    b'ecdsa-sha2-nistp256': ec.SECP256R1(),
    b'ecdsa-sha2-nistp384': ec.SECP384R1(),
    b'ecdsa-sha2-nistp521': ec.SECP521R1(),
}

_secToNist = {
    b'secp256r1' : b'nistp256',
    b'secp384r1' : b'nistp384',
    b'secp521r1' : b'nistp521',
}


_ecSizeTable = {
    256: ec.SECP256R1(),
    384: ec.SECP384R1(),
    521: ec.SECP521R1(),
}

class BadFingerPrintFormat(Exception):
    """
    Raises when unsupported fingerprint formats are presented to fingerprint.
    """



class FingerprintFormats(Names):
    """
    Constants representing the supported formats of key fingerprints.

    @cvar MD5_HEX: Named constant representing fingerprint format generated
        using md5[RFC1321] algorithm in hexadecimal encoding.
    @type MD5_HEX: L{twisted.python.constants.NamedConstant}

    @cvar SHA256_BASE64: Named constant representing fingerprint format
        generated using sha256[RFC4634] algorithm in base64 encoding
    @type SHA256_BASE64: L{NamedConstant}
    @cvar SHA1_BASE64: Named constant representing fingerprint format
        generated using sha1[RFC3174] algorithm in base64 encoding
    @type SHA1_BASE64: L{NamedConstant}
    """

    MD5_HEX = NamedConstant()
    SHA256_BASE64 = NamedConstant()
    SHA1_BASE64 = NamedConstant()


class PassphraseNormalizationError(Exception):
    """
    Raised when a passphrase contains Unicode characters that cannot be
    normalized using the available Unicode character database.
    """


def _normalizePassphrase(passphrase):
    """
    Normalize a passphrase, which may be Unicode.

    If the passphrase is Unicode, this follows the requirements of U{NIST
    800-63B, section
    5.1.1.2<https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver>}
    for Unicode characters in memorized secrets: it applies the
    Normalization Process for Stabilized Strings using NFKC normalization.
    The passphrase is then encoded using UTF-8.

    @type passphrase: L{bytes} or L{unicode} or L{None}
    @param passphrase: The passphrase to normalize.

    @return: The normalized passphrase, if any.
    @rtype: L{bytes} or L{None}
    @raises PassphraseNormalizationError: if the passphrase is Unicode and
    cannot be normalized using the available Unicode character database.
    """
    if isinstance(passphrase, unicode):
        # The Normalization Process for Stabilized Strings requires aborting
        # with an error if the string contains any unassigned code point.
        if any(unicodedata.category(c) == "Cn" for c in passphrase):
            # Perhaps not very helpful, but we don't want to leak any other
            # information about the passphrase.
            raise PassphraseNormalizationError()
        return unicodedata.normalize("NFKC", passphrase).encode("UTF-8")
    else:
        return passphrase


class Key(object):
    """
    An object representing a key.  A key can be either a public or
    private key.  A public key can verify a signature; a private key can
    create or verify a signature.  To generate a string that can be stored
    on disk, use the toString method.  If you have a private key, but want
    the string representation of the public key, use Key.public().toString().

    SSH Transport local-peer Key: (PrivateKey)
       * fromCryptograpyObject / __init__ - for local peer private key
       * blob() - return public blob - for handshake / sign payload
       * sign - for local peer private key

    SSH Transport remote-peer key /PublicKey):
       * fromPublicBlob() / __init__  - for remote peer public key
       * verify - for remote peer

    SSH Key:
       * fromString / __init__
       * toString
       * getFormat - human readable representation of internal guessed type
       * getCryptographyObject

    generate_ssh_key(type, size) -> external helper
    """

    @classmethod
    def fromFile(cls, filename, type=None, passphrase=None, encoding='utf-8'):
        """
        Load a key from a file.

        @param filename: The path to load key data from.

        @type type: L{str} or L{None}
        @param type: A string describing the format the key data is in, or
        L{None} to attempt detection of the type.

        @type passphrase: L{bytes} or L{None}
        @param passphrase: The passphrase the key is encrypted with, or L{None}
        if there is no encryption.

        @rtype: L{Key}
        @return: The loaded key.
        """
        with open(_path(filename, encoding), 'rb') as file:
            return cls.fromString(file.read(), type, passphrase)

    @classmethod
    def fromString(cls, data, type=None, passphrase=None):
        """
        Return a Key object corresponding to the string data.
        type is optionally the type of string, matching a _fromString_*
        method.  Otherwise, the _guessStringType() classmethod will be used
        to guess a type.  If the key is encrypted, passphrase is used as
        the decryption key.

        @type data: L{bytes}
        @param data: The key data.

        @type type: L{str} or L{None}
        @param type: A string describing the format the key data is in, or
        L{None} to attempt detection of the type.

        @type passphrase: L{bytes} or L{None}
        @param passphrase: The passphrase the key is encrypted with, or L{None}
        if there is no encryption.

        @rtype: L{Key}
        @return: The loaded key.
        """
        if isinstance(data, unicode):
            data = data.encode("utf-8")
        passphrase = _normalizePassphrase(passphrase)
        if type is None:
            type = cls._guessStringType(data)
        if type is None:
            raise BadKeyError(
                'Cannot guess the type for %r' % force_unicode(data[:80]))

        try:
            method = getattr(cls, '_fromString_%s' % type.upper(), None)
            if method is None:
                raise BadKeyError(
                    'no _fromString method for %r' % force_unicode(type[:30]))
            if method.__code__.co_argcount == 2:  # no passphrase
                if passphrase:
                    raise BadKeyError('key not encrypted')
                return method(data)
            else:
                return method(data, passphrase)
        except (IndexError):
            # Most probably some parts are missing from the key, so
            # we consider it too short.
            raise BadKeyError('Key is too short.')
        except (struct.error, binascii.Error, TypeError):
            raise BadKeyError('Fail to parse key content.')

    @classmethod
    def _fromString_BLOB(cls, blob):
        """
        Return a public key object corresponding to this public key blob.

        The format of a RSA public key blob is::
            string 'ssh-rsa'
            integer e
            integer n

        The format of a DSA public key blob is::
            string 'ssh-dss'
            integer p
            integer q
            integer g
            integer y

        The format of ECDSA-SHA2-* public key blob is::
            string 'ecdsa-sha2-[identifier]'
            integer x
            integer y

            identifier is the standard NIST curve name.

        The format of an Ed25519 public key blob is::
            string 'ssh-ed25519'
            string a

        @type blob: L{bytes}
        @param blob: The key data.

        @return: A new key.
        @rtype: L{twisted.conch.ssh.keys.Key}
        @raises BadKeyError: if the key type (the first string) is unknown.
        """
        keyType, rest = common.getNS(blob)
        if keyType == b'ssh-rsa':
            e, n, rest = common.getMP(rest, 2)
            return cls._fromRSAComponents(n, e)
        elif keyType == b'ssh-dss':
            p, q, g, y, rest = common.getMP(rest, 4)
            return cls._fromDSAComponents( y, p, q, g)
        elif keyType in _curveTable:
            return cls._fromECEncodedPoint(
                encodedPoint=common.getNS(rest, 2)[1],
                curve=keyType,
                )
        elif keyType == b'ssh-ed25519':
            a, rest = common.getNS(rest)
            return cls._fromEd25519Components(a)
        else:
            raise BadKeyError("unknown blob type: {}".format(
                force_unicode(keyType[:30])))

    @classmethod
    def _fromString_PRIVATE_BLOB(cls, blob):
        """
        Return a private key object corresponding to this private key blob.
        The blob formats are as follows:

        RSA keys::
            string 'ssh-rsa'
            integer n
            integer e
            integer d
            integer u
            integer p
            integer q

        DSA keys::
            string 'ssh-dss'
            integer p
            integer q
            integer g
            integer y
            integer x

        EC keys::
            string 'ecdsa-sha2-[identifier]'
            string identifier
            string q
            integer privateValue

            identifier is the standard NIST curve name.

        Ed25519 keys::
            string 'ssh-ed25519'
            string a
            string k || a


        @type blob: L{bytes}
        @param blob: The key data.

        @return: A new key.
        @rtype: L{twisted.conch.ssh.keys.Key}
        @raises BadKeyError: if
            * the key type (the first string) is unknown
            * the curve name of an ECDSA key does not match the key type
        """
        keyType, rest = common.getNS(blob)

        if keyType == b'ssh-rsa':
            n, e, d, u, p, q, rest = common.getMP(rest, 6)
            return cls._fromRSAComponents(n=n, e=e, d=d, p=p, q=q)
        elif keyType == b'ssh-dss':
            p, q, g, y, x, rest = common.getMP(rest, 5)
            return cls._fromDSAComponents(y=y, g=g, p=p, q=q, x=x)
        elif keyType in _curveTable:
            curve = _curveTable[keyType]
            curveName, q, rest = common.getNS(rest, 2)
            if curveName != _secToNist[curve.name.encode('ascii')]:
                raise BadKeyError(
                    'ECDSA curve name %r does not match key type %r' % (
                        force_unicode(curveName), force_unicode(keyType)))
            privateValue, rest = common.getMP(rest)
            return cls._fromECEncodedPoint(
                encodedPoint=q, curve=keyType, privateValue=privateValue)
        elif keyType == b'ssh-ed25519':
            # OpenSSH's format repeats the public key bytes for some reason.
            # We're only interested in the private key here anyway.
            a, combined, rest = common.getNS(rest, 2)
            k = combined[:32]
            return cls._fromEd25519Components(a, k=k)
        else:
            raise BadKeyError(
                'Unknown blob type: %r' % force_unicode(keyType[:30]))


    @classmethod
    def _fromString_PUBLIC_OPENSSH(cls, data):
        """
        Return a public key object corresponding to this OpenSSH public key
        string.  The format of an OpenSSH public key string is::
            <key type> <base64-encoded public key blob>

        @type data: L{bytes}
        @param data: The key data.

        @return: A new key.
        @rtype: L{twisted.conch.ssh.keys.Key}
        @raises BadKeyError: if the blob type is unknown.
        """
        # ECDSA keys don't need base64 decoding which is required
        # for RSA or DSA key.
        if data.startswith(b'ecdsa-sha2'):
            return cls(load_ssh_public_key(data, default_backend()))
        blob = decodebytes(data.split()[1])
        return cls._fromString_BLOB(blob)


    @classmethod
    def _fromString_PRIVATE_OPENSSH_V1(cls, data, passphrase):
        """
        Return a private key object corresponding to this OpenSSH private key
        string, in the "openssh-key-v1" format introduced in OpenSSH 6.5.

        The format of an openssh-key-v1 private key string is::
            -----BEGIN OPENSSH PRIVATE KEY-----
            <base64-encoded SSH protocol string>
            -----END OPENSSH PRIVATE KEY-----

        The SSH protocol string is as described in
        U{PROTOCOL.key<https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key>}.

        @type data: L{bytes}
        @param data: The key data.

        @type passphrase: L{bytes} or L{None}
        @param passphrase: The passphrase the key is encrypted with, or L{None}
        if it is not encrypted.

        @return: A new key.
        @rtype: L{twisted.conch.ssh.keys.Key}
        @raises BadKeyError: if
            * a passphrase is provided for an unencrypted key
            * the SSH protocol encoding is incorrect
        @raises EncryptedKeyError: if
            * a passphrase is not provided for an encrypted key
        """
        lines = data.strip().splitlines()
        keyList = decodebytes(b''.join(lines[1:-1]))
        if not keyList.startswith(b'openssh-key-v1\0'):
            raise BadKeyError('unknown OpenSSH private key format')
        keyList = keyList[len(b'openssh-key-v1\0'):]
        cipher, kdf, kdfOptions, rest = common.getNS(keyList, 3)
        n = struct.unpack('!L', rest[:4])[0]
        if n != 1:
            raise BadKeyError('only OpenSSH private key files containing '
                              'a single key are supported')
        # Ignore public key
        _, encPrivKeyList, _ = common.getNS(rest[4:], 2)
        if cipher != b'none':
            if not passphrase:
                raise EncryptedKeyError('Passphrase must be provided '
                                        'for an encrypted key')
            # Determine cipher
            if cipher in (b'aes128-ctr', b'aes192-ctr', b'aes256-ctr'):
                algorithmClass = algorithms.AES
                blockSize = 16
                keySize = int(cipher[3:6]) // 8
                ivSize = blockSize
            else:
                raise BadKeyError('unknown encryption type %r' % (
                    force_unicode(cipher),))
            if kdf == b'bcrypt':
                salt, rest = common.getNS(kdfOptions)
                rounds = struct.unpack('!L', rest[:4])[0]
                decKey = bcrypt.kdf(
                    passphrase, salt, keySize + ivSize, rounds,
                    # We can only use the number of rounds that OpenSSH used.
                    ignore_few_rounds=True)
            else:
                raise BadKeyError(
                    'unknown KDF type %r' % (force_unicode(kdf),))
            if (len(encPrivKeyList) % blockSize) != 0:
                raise BadKeyError('bad padding')
            decryptor = Cipher(
                algorithmClass(decKey[:keySize]),
                modes.CTR(decKey[keySize:keySize + ivSize]),
                backend=default_backend()
            ).decryptor()
            privKeyList = (
                decryptor.update(encPrivKeyList) + decryptor.finalize())
        else:
            if kdf != b'none':
                raise BadKeyError('private key specifies KDF %r but no '
                                  'cipher' % (force_unicode(kdf),))
            privKeyList = encPrivKeyList
        check1 = struct.unpack('!L', privKeyList[:4])[0]
        check2 = struct.unpack('!L', privKeyList[4:8])[0]
        if check1 != check2:
            raise BadKeyError(
                'Private key sanity check failed. Maybe invalid passphrase.')
        return cls._fromString_PRIVATE_BLOB(privKeyList[8:])


    @classmethod
    def _fromString_PRIVATE_OPENSSH(cls, data, passphrase):
        """
        Return a private key object corresponding to this OpenSSH private key
        string, in the old PEM-based format.

        The format of a PEM-based OpenSSH private key string is::
            -----BEGIN <key type> PRIVATE KEY-----
            [Proc-Type: 4,ENCRYPTED
            DEK-Info: DES-EDE3-CBC,<initialization value>]
            <base64-encoded ASN.1 structure>
            ------END <key type> PRIVATE KEY------

        The ASN.1 structure of a RSA key is::
            (0, n, e, d, p, q)

        The ASN.1 structure of a DSA key is::
            (0, p, q, g, y, x)

        The ASN.1 structure of a ECDSA key is::
            (ECParameters, OID, NULL)

        @type data: L{bytes}
        @param data: The key data.

        @type passphrase: L{bytes} or L{None}
        @param passphrase: The passphrase the key is encrypted with, or L{None}
        if it is not encrypted.

        @return: A new key.
        @rtype: L{twisted.conch.ssh.keys.Key}
        @raises BadKeyError: if
            * a passphrase is provided for an unencrypted key
            * the ASN.1 encoding is incorrect
        @raises EncryptedKeyError: if
            * a passphrase is not provided for an encrypted key
        """
        lines = data.strip().splitlines()
        kind = lines[0][11:-17]
        if lines[1].startswith(b'Proc-Type: 4,ENCRYPTED'):
            if not passphrase:
                raise EncryptedKeyError('Passphrase must be provided '
                                        'for an encrypted key')

            # Determine cipher and initialization vector
            try:
                _, cipherIVInfo = lines[2].split(b' ', 1)
                cipher, ivdata = cipherIVInfo.rstrip().split(b',', 1)
            except ValueError:
                raise BadKeyError(
                    'invalid DEK-info %r' % (force_unicode(lines[2]),))

            if cipher in (b'AES-128-CBC', b'AES-256-CBC'):
                algorithmClass = algorithms.AES
                keySize = int(cipher.split(b'-')[1]) // 8
                if len(ivdata) != 32:
                    raise BadKeyError('AES encrypted key with a bad IV')
            elif cipher == b'DES-EDE3-CBC':
                algorithmClass = algorithms.TripleDES
                keySize = 24
                if len(ivdata) != 16:
                    raise BadKeyError('DES encrypted key with a bad IV')
            else:
                raise BadKeyError(
                    'unknown encryption type %r' % (force_unicode(cipher),))

            # Extract keyData for decoding
            iv = bytes(bytearray([int(ivdata[i:i + 2], 16)
                                  for i in range(0, len(ivdata), 2)]))
            ba = md5(passphrase + iv[:8]).digest()
            bb = md5(ba + passphrase + iv[:8]).digest()
            decKey = (ba + bb)[:keySize]
            b64Data = decodebytes(b''.join(lines[3:-1]))

            decryptor = Cipher(
                algorithmClass(decKey),
                modes.CBC(iv),
                backend=default_backend()
            ).decryptor()
            keyData = decryptor.update(b64Data) + decryptor.finalize()

            removeLen = ord(keyData[-1:])
            keyData = keyData[:-removeLen]
        else:
            b64Data = b''.join(lines[1:-1])
            keyData = decodebytes(b64Data)

        try:
            decodedKey = berDecoder.decode(keyData)[0]
        except PyAsn1Error as e:
            raise BadKeyError(
                'Failed to decode key (Bad Passphrase?): %s' % (
                    force_unicode(e),))

        if kind == b'EC':
            return cls(
                load_pem_private_key(data, passphrase, default_backend()))

        if kind == b'RSA':
            if len(decodedKey) == 2:  # Alternate RSA key
                decodedKey = decodedKey[0]
            if len(decodedKey) < 6:
                raise BadKeyError('RSA key failed to decode properly')

            n, e, d, p, q, dmp1, dmq1, iqmp = [
                long(value) for value in decodedKey[1:9]
                ]
            return cls(
                rsa.RSAPrivateNumbers(
                    p=p,
                    q=q,
                    d=d,
                    dmp1=dmp1,
                    dmq1=dmq1,
                    iqmp=iqmp,
                    public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
                ).private_key(default_backend())
            )
        elif kind == b'DSA':
            p, q, g, y, x = [long(value) for value in decodedKey[1: 6]]
            if len(decodedKey) < 6:
                raise BadKeyError('DSA key failed to decode properly')
            return cls._fromDSAComponents(y, p, q, g, x)
        else:
            raise BadKeyError("unknown key type %s" % (force_unicode(kind),))


    @classmethod
    def _fromString_PUBLIC_LSH(cls, data):
        """
        Return a public key corresponding to this LSH public key string.
        The LSH public key string format is::
            <s-expression: ('public-key', (<key type>, (<name, <value>)+))>

        The names for a RSA (key type 'rsa-pkcs1-sha1') key are: n, e.
        The names for a DSA (key type 'dsa') key are: y, g, p, q.

        @type data: L{bytes}
        @param data: The key data.

        @return: A new key.
        @rtype: L{twisted.conch.ssh.keys.Key}
        @raises BadKeyError: if the key type is unknown
        """
        sexp = sexpy.parse(decodebytes(data[1:-1]))
        assert sexp[0] == b'public-key'
        kd = {}
        for name, data in sexp[1][1:]:
            kd[name] = common.getMP(common.NS(data))[0]
        if sexp[1][0] == b'dsa':
            return cls._fromDSAComponents(
                y=kd[b'y'], g=kd[b'g'], p=kd[b'p'], q=kd[b'q'])

        elif sexp[1][0] == b'rsa-pkcs1-sha1':
            return cls._fromRSAComponents(n=kd[b'n'], e=kd[b'e'])
        else:
            raise BadKeyError('unknown lsh key type %r' % (
                force_unicode(sexp[1][0][:30]),))

    @classmethod
    def _fromString_PRIVATE_LSH(cls, data):
        """
        Return a private key corresponding to this LSH private key string.
        The LSH private key string format is::
            <s-expression: ('private-key', (<key type>, (<name>, <value>)+))>

        The names for a RSA (key type 'rsa-pkcs1-sha1') key are: n, e, d, p, q.
        The names for a DSA (key type 'dsa') key are: y, g, p, q, x.

        @type data: L{bytes}
        @param data: The key data.

        @return: A new key.
        @rtype: L{twisted.conch.ssh.keys.Key}
        @raises BadKeyError: if the key type is unknown
        """
        sexp = sexpy.parse(data)
        assert sexp[0] == b'private-key'
        kd = {}
        for name, data in sexp[1][1:]:
            kd[name] = common.getMP(common.NS(data))[0]
        if sexp[1][0] == b'dsa':
            assert len(kd) == 5, len(kd)
            return cls._fromDSAComponents(
                y=kd[b'y'], g=kd[b'g'], p=kd[b'p'], q=kd[b'q'], x=kd[b'x'])
        elif sexp[1][0] == b'rsa-pkcs1':
            assert len(kd) == 8, len(kd)
            if kd[b'p'] > kd[b'q']:  # Make p smaller than q
                kd[b'p'], kd[b'q'] = kd[b'q'], kd[b'p']
            return cls._fromRSAComponents(
                n=kd[b'n'], e=kd[b'e'], d=kd[b'd'], p=kd[b'p'], q=kd[b'q'])

        else:
            raise BadKeyError(
                'unknown lsh key type %r' % (force_unicode(sexp[1][0][:30]),))

    @classmethod
    def _fromString_AGENTV3(cls, data):
        """
        Return a private key object corresponsing to the Secure Shell Key
        Agent v3 format.

        The SSH Key Agent v3 format for a RSA key is::
            string 'ssh-rsa'
            integer e
            integer d
            integer n
            integer u
            integer p
            integer q

        The SSH Key Agent v3 format for a DSA key is::
            string 'ssh-dss'
            integer p
            integer q
            integer g
            integer y
            integer x

        @type data: L{bytes}
        @param data: The key data.

        @return: A new key.
        @rtype: L{twisted.conch.ssh.keys.Key}
        @raises BadKeyError: if the key type (the first string) is unknown
        """
        keyType, data = common.getNS(data)
        if keyType == b'ssh-dss':
            p, data = common.getMP(data)
            q, data = common.getMP(data)
            g, data = common.getMP(data)
            y, data = common.getMP(data)
            x, data = common.getMP(data)
            return cls._fromDSAComponents(y=y, g=g, p=p, q=q, x=x)
        elif keyType == b'ssh-rsa':
            e, data = common.getMP(data)
            d, data = common.getMP(data)
            n, data = common.getMP(data)
            u, data = common.getMP(data)
            p, data = common.getMP(data)
            q, data = common.getMP(data)
            return cls._fromRSAComponents(n=n, e=e, d=d, p=p, q=q, u=u)
        else:  # pragma: no cover
            raise BadKeyError(
                "unknown key type %r" % (force_unicode(keyType[:30]),))

    @classmethod
    def _guessStringType(cls, data):
        """
        Guess the type of key in data.  The types map to _fromString_*
        methods.

        @type data: L{bytes}
        @param data: The key data.
        """
        if data.startswith(b'ssh-') or data.startswith(b'ecdsa-sha2-'):
            return 'public_openssh'
        elif data.startswith(b'---- BEGIN SSH2 PUBLIC KEY ----'):
            return 'public_sshcom'
        elif data.startswith(b'---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----'):
            return 'private_sshcom'
        elif data.startswith(b'-----BEGIN RSA PUBLIC'):
            return 'public_pkcs1_rsa'
        elif (
            data.startswith(b'-----BEGIN RSA PRIVATE') or
            data.startswith(b'-----BEGIN DSA PRIVATE') or
            data.startswith(b'-----BEGIN EC PRIVATE')
                ):
            # This is also private PKCS#1 format.
            return 'private_openssh'
        elif data.startswith(b'-----BEGIN OPENSSH PRIVATE KEY-----'):
            return 'private_openssh_v1'

        elif data.startswith(b'-----BEGIN CERTIFICATE-----'):
            return 'public_x509_certificate'

        elif data.startswith(b'-----BEGIN PUBLIC KEY-----'):
            # Public Key in X.509 format it's as follows
            return 'public_x509'

        elif data.startswith(b'-----BEGIN PRIVATE KEY-----'):
            return 'private_pkcs8'
        elif data.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
            return 'private_encrypted_pkcs8'
        elif data.startswith(b'PuTTY-User-Key-File-2'):
            return 'private_putty'
        elif data.startswith(b'{'):
            return 'public_lsh'
        elif data.startswith(b'('):
            return 'private_lsh'
        elif (data.startswith(b'\x00\x00\x00\x07ssh-') or
              data.startswith(b'\x00\x00\x00\x13ecdsa-') or
              data.startswith(b'\x00\x00\x00\x0bssh-ed25519')):
            ignored, rest = common.getNS(data)
            count = 0
            while rest:
                count += 1
                ignored, rest = common.getMP(rest)
            if count > 4:
                return 'agentv3'
            else:
                return 'blob'

    @classmethod
    def _fromRSAComponents(cls, n, e, d=None, p=None, q=None, u=None):
        """
        Build a key from RSA numerical components.

        @type n: L{int}
        @param n: The 'n' RSA variable.

        @type e: L{int}
        @param e: The 'e' RSA variable.

        @type d: L{int} or L{None}
        @param d: The 'd' RSA variable (optional for a public key).

        @type p: L{int} or L{None}
        @param p: The 'p' RSA variable (optional for a public key).

        @type q: L{int} or L{None}
        @param q: The 'q' RSA variable (optional for a public key).

        @type u: L{int} or L{None}
        @param u: The 'u' RSA variable. Ignored, as its value is determined by
        p and q.

        @rtype: L{Key}
        @return: An RSA key constructed from the values as given.
        """
        publicNumbers = rsa.RSAPublicNumbers(e=e, n=n)
        if d is None:
            # We have public components.
            keyObject = publicNumbers.public_key(default_backend())
        else:
            privateNumbers = rsa.RSAPrivateNumbers(
                p=p,
                q=q,
                d=d,
                dmp1=rsa.rsa_crt_dmp1(d, p),
                dmq1=rsa.rsa_crt_dmq1(d, q),
                iqmp=rsa.rsa_crt_iqmp(p, q),
                public_numbers=publicNumbers,
            )
            keyObject = privateNumbers.private_key(default_backend())

        return cls(keyObject)

    @classmethod
    def _fromDSAComponents(cls, y, p, q, g, x=None):
        """
        Build a key from DSA numerical components.

        @type y: L{int}
        @param y: The 'y' DSA variable.

        @type p: L{int}
        @param p: The 'p' DSA variable.

        @type q: L{int}
        @param q: The 'q' DSA variable.

        @type g: L{int}
        @param g: The 'g' DSA variable.

        @type x: L{int} or L{None}
        @param x: The 'x' DSA variable (optional for a public key)

        @rtype: L{Key}
        @return: A DSA key constructed from the values as given.
        """
        publicNumbers = dsa.DSAPublicNumbers(
            y=y, parameter_numbers=dsa.DSAParameterNumbers(p=p, q=q, g=g))

        if x is None:
            try:
                # We have public components.
                keyObject = publicNumbers.public_key(default_backend())
                return cls(keyObject)
            except ValueError as error:
                raise BadKeyError(
                    'Unsupported DSA public key: %s' % (force_unicode(error),))

        try:
            privateNumbers = dsa.DSAPrivateNumbers(
                x=x, public_numbers=publicNumbers)
            keyObject = privateNumbers.private_key(default_backend())
        except ValueError as error:
            raise BadKeyError(
                'Unsupported DSA private key: %s' % (force_unicode(error),))

        return cls(keyObject)

    @classmethod
    def _fromECComponents(cls, x, y, curve, privateValue=None):
        """
        Build a key from EC components.

        @param x: The affine x component of the public point used for verifying.
        @type x: L{int}

        @param y: The affine y component of the public point used for verifying.
        @type y: L{int}

        @param curve: NIST name of elliptic curve.
        @type curve: L{bytes}

        @param privateValue: The private value.
        @type privateValue: L{int}
        """

        publicNumbers = ec.EllipticCurvePublicNumbers(
            x=x, y=y, curve=_curveTable[curve])
        if privateValue is None:
            # We have public components.
            keyObject = publicNumbers.public_key(default_backend())
        else:
            privateNumbers = ec.EllipticCurvePrivateNumbers(
                private_value=privateValue, public_numbers=publicNumbers)
            keyObject = privateNumbers.private_key(default_backend())

        return cls(keyObject)

    @classmethod
    def _fromECEncodedPoint(cls, encodedPoint, curve, privateValue=None):
        """
        Build a key from an EC encoded point.

        @param encodedPoint: The public point encoded as in SEC 1 v2.0
        section 2.3.3.
        @type encodedPoint: L{bytes}

        @param curve: NIST name of elliptic curve.
        @type curve: L{bytes}

        @param privateValue: The private value.
        @type privateValue: L{int}
        """

        if privateValue is None:
            # We have public components.
            keyObject = ec.EllipticCurvePublicKey.from_encoded_point(
                _curveTable[curve], encodedPoint
            )
        else:
            keyObject = ec.derive_private_key(
                privateValue, _curveTable[curve], default_backend()
            )

        return cls(keyObject)

    @classmethod
    def _fromEd25519Components(cls, a, k=None):
        """Build a key from Ed25519 components.

        @param a: The Ed25519 public key, as defined in RFC 8032 section
            5.1.5.
        @type a: L{bytes}

        @param k: The Ed25519 private key, as defined in RFC 8032 section
            5.1.5.
        @type k: L{bytes}
        """

        if k is None:
            keyObject = ed25519.Ed25519PublicKey.from_public_bytes(a)
        else:
            keyObject = ed25519.Ed25519PrivateKey.from_private_bytes(k)

        return cls(keyObject)

    def __init__(self, keyObject):
        """
        Initialize with a private or public
        C{cryptography.hazmat.primitives.asymmetric} key.

        @param keyObject: Low level key.
        @type keyObject: C{cryptography.hazmat.primitives.asymmetric} key.
        """
        self._keyObject = keyObject

    def __eq__(self, other):
        """
        Return True if other represents an object with the same key.
        """
        if type(self) == type(other):
            return self.type() == other.type() and self.data() == other.data()
        else:
            return NotImplemented

    def __ne__(self, other):
        """
        Return True if other represents anything other than this key.
        """
        result = self.__eq__(other)
        if result == NotImplemented:
            return result
        return not result

    def __repr__(self):
        """
        Return a pretty representation of this object.
        """
        if self.type() == 'EC':
            data = self.data()
            name = data['curve'].decode('utf-8')

            if self.isPublic():
                out = '<Elliptic Curve Public Key (%s bits)' % (name[-3:],)
            else:
                out = '<Elliptic Curve Private Key (%s bits)' % (name[-3:],)

            for k, v in sorted(data.items()):
                out += "\n%s:\n\t%s" % (k, v)

            return out + ">\n"
        else:
            lines = [
                '<%s %s (%s bits)' % (
                    self.type(),
                    self.isPublic() and 'Public Key' or 'Private Key',
                    self.size())]
            for k, v in sorted(self.data().items()):
                lines.append('attr %s:' % (k,))
                by = v if self.type() == 'Ed25519' else common.MP(v)[4:]
                while by:
                    m = by[:15]
                    by = by[15:]
                    o = ''
                    for c in iterbytes(m):
                        o = o + '%02x:' % (ord(c),)
                    if len(m) < 15:
                        o = o[:-1]
                    lines.append('\t' + o)
            lines[-1] = lines[-1] + '>'
            return '\n'.join(lines)

    def isPublic(self):
        """
        Check if this instance is a public key.

        @return: C{True} if this is a public key.
        """
        return isinstance(
            self._keyObject,
            (rsa.RSAPublicKey, dsa.DSAPublicKey, ec.EllipticCurvePublicKey,
             ed25519.Ed25519PublicKey))

    def public(self):
        """
        Returns a version of this key containing only the public key data.
        If this is a public key, this may or may not be the same object
        as self.

        @rtype: L{Key}
        @return: A public key.
        """
        if self.isPublic():
            return self
        else:
            return Key(self._keyObject.public_key())

    def fingerprint(self, format=FingerprintFormats.MD5_HEX):
        """
        The fingerprint of a public key consists of the output of the
        message-digest algorithm in the specified format.
        Supported formats include L{FingerprintFormats.MD5_HEX},
        L{FingerprintFormats.SHA256_BASE64} and
        L{FingerprintFormats.SHA1_BASE64}

        The input to the algorithm is the public key data as specified by [RFC4253].

        The output of sha256[RFC4634] and sha1[RFC3174] algorithms are
        presented to the user in the form of base64 encoded sha256 and sha1
        hashes, respectively.
        Examples:
            C{US5jTUa0kgX5ZxdqaGF0yGRu8EgKXHNmoT8jHKo1StM=}
            C{9CCuTybG5aORtuW4jrFcp0PbK4U=}

        The output of the MD5[RFC1321](default) algorithm is presented to the user as
        a sequence of 16 octets printed as hexadecimal with lowercase letters
        and separated by colons.
        Example: C{c1:b1:30:29:d7:b8:de:6c:97:77:10:d7:46:41:63:87}

        @param format: Format for fingerprint generation. Consists
            hash function and representation format.
            Default is L{FingerprintFormats.MD5_HEX}

        @since: 8.2

        @return: the user presentation of this L{Key}'s fingerprint, as a
        string.

        @rtype: L{str}
        """
        if format is FingerprintFormats.SHA256_BASE64:
            return base64.b64encode(
                sha256(self.blob()).digest()).decode('ascii')
        elif format is FingerprintFormats.SHA1_BASE64:
            return base64.b64encode(
                sha1(self.blob()).digest()).decode('ascii')
        elif format is FingerprintFormats.MD5_HEX:
            return ':'.join([binascii.hexlify(x)
                             for x in iterbytes(md5(self.blob()).digest())])
        else:
            raise BadFingerPrintFormat(
                'Unsupported fingerprint format: %s' % (format,))

    def type(self):
        """
        Return the type of the object we wrap.  Currently this can only be
        'RSA', 'DSA', 'EC', or 'Ed25519'.

        @rtype: L{str}
        @raises RuntimeError: If the object type is unknown.
        """
        if isinstance(
                self._keyObject, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
            return 'RSA'
        elif isinstance(
                self._keyObject, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
            return 'DSA'
        elif isinstance(
                self._keyObject,
                (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
            return 'EC'
        elif isinstance(
                self._keyObject,
                (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
            return 'Ed25519'
        else:
            raise RuntimeError(
                'unknown type of object: %r' % (self._keyObject,))

    def sshType(self):
        """
        Get the type of the object we wrap as defined in the SSH protocol,
        defined in RFC 4253, Section 6.6. Currently this can only be b'ssh-rsa',
        b'ssh-dss' or b'ecdsa-sha2-[identifier]'.

        identifier is the standard NIST curve name

        @return: The key type format.
        @rtype: L{bytes}
        """
        if self.type() == 'EC':
            return (
                b'ecdsa-sha2-' +
                _secToNist[self._keyObject.curve.name.encode('ascii')])
        else:
            return {
                'RSA': b'ssh-rsa',
                'DSA': b'ssh-dss',
                'Ed25519': b'ssh-ed25519',
            }[self.type()]

    def size(self):
        """
        Return the size of the object we wrap.

        @return: The size of the key.
        @rtype: L{int}
        """
        if self._keyObject is None:
            return 0
        elif self.type() == 'EC':
            return self._keyObject.curve.key_size
        elif self.type() == 'Ed25519':
            return 256
        return self._keyObject.key_size

    def data(self):
        """
        Return the values of the public key as a dictionary.

        @rtype: L{dict}
        """
        if isinstance(self._keyObject, rsa.RSAPublicKey):
            numbers = self._keyObject.public_numbers()
            return {
                "n": numbers.n,
                "e": numbers.e,
            }
        elif isinstance(self._keyObject, rsa.RSAPrivateKey):
            numbers = self._keyObject.private_numbers()
            return {
                "n": numbers.public_numbers.n,
                "e": numbers.public_numbers.e,
                "d": numbers.d,
                "p": numbers.p,
                "q": numbers.q,
                # Use a trick: iqmp is q^-1 % p, u is p^-1 % q
                "u": rsa.rsa_crt_iqmp(numbers.q, numbers.p),
            }
        elif isinstance(self._keyObject, dsa.DSAPublicKey):
            numbers = self._keyObject.public_numbers()
            return {
                "y": numbers.y,
                "g": numbers.parameter_numbers.g,
                "p": numbers.parameter_numbers.p,
                "q": numbers.parameter_numbers.q,
            }
        elif isinstance(self._keyObject, dsa.DSAPrivateKey):
            numbers = self._keyObject.private_numbers()
            return {
                "x": numbers.x,
                "y": numbers.public_numbers.y,
                "g": numbers.public_numbers.parameter_numbers.g,
                "p": numbers.public_numbers.parameter_numbers.p,
                "q": numbers.public_numbers.parameter_numbers.q,
            }
        elif isinstance(self._keyObject, ec.EllipticCurvePublicKey):
            numbers = self._keyObject.public_numbers()
            return {
                "x": numbers.x,
                "y": numbers.y,
                "curve": self.sshType(),
            }
        elif isinstance(self._keyObject, ec.EllipticCurvePrivateKey):
            numbers = self._keyObject.private_numbers()
            return {
                "x": numbers.public_numbers.x,
                "y": numbers.public_numbers.y,
                "privateValue": numbers.private_value,
                "curve": self.sshType(),
            }
        elif isinstance(self._keyObject, ed25519.Ed25519PublicKey):
            return {
                "a": self._keyObject.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw
                ),
            }
        elif isinstance(self._keyObject, ed25519.Ed25519PrivateKey):
            return {
                "a": self._keyObject.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw
                ),
                "k": self._keyObject.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption()
                ),
            }

        else:
            raise RuntimeError("Unexpected key type: %s" % (self._keyObject,))

    def blob(self):
        """
        Return the public key blob for this key. The blob is the
        over-the-wire format for public keys.

        SECSH-TRANS RFC 4253 Section 6.6.

        RSA keys::
            string 'ssh-rsa'
            integer e
            integer n

        DSA keys::
            string 'ssh-dss'
            integer p
            integer q
            integer g
            integer y

        EC keys::
            string 'ecdsa-sha2-[identifier]'
            integer x
            integer y

            identifier is the standard NIST curve name

        Ed25519 keys::
            string 'ssh-ed25519'
            string a

        @rtype: L{bytes}
        """
        type = self.type()
        data = self.data()
        if type == 'RSA':
            return (common.NS(b'ssh-rsa') + common.MP(data['e']) +
                    common.MP(data['n']))
        elif type == 'DSA':
            return (common.NS(b'ssh-dss') + common.MP(data['p']) +
                    common.MP(data['q']) + common.MP(data['g']) +
                    common.MP(data['y']))
        elif type == 'EC':
            byteLength = (self._keyObject.curve.key_size + 7) // 8
            return (
                common.NS(data['curve']) + common.NS(data["curve"][-8:]) +
                common.NS(
                    b'\x04' + utils.int_to_bytes(data['x'], byteLength) +
                    utils.int_to_bytes(data['y'], byteLength)))
        elif type == 'Ed25519':
            return common.NS(b'ssh-ed25519') + common.NS(data['a'])
        else:
            raise BadKeyError('unknown key type: %s' % (force_unicode(type,)))


    def privateBlob(self):
        """
        Return the private key blob for this key. The blob is the
        over-the-wire format for private keys:

        Specification in OpenSSH PROTOCOL.agent

        RSA keys::
            string 'ssh-rsa'
            integer n
            integer e
            integer d
            integer u
            integer p
            integer q

        DSA keys::
            string 'ssh-dss'
            integer p
            integer q
            integer g
            integer y
            integer x

        EC keys::
            string 'ecdsa-sha2-[identifier]'
            integer x
            integer y
            integer privateValue

            identifier is the NIST standard curve name.

        Ed25519 keys:
            string 'ssh-ed25519'
            string a
            string k || a
        """
        type = self.type()
        data = self.data()
        if type == 'RSA':
            iqmp = rsa.rsa_crt_iqmp(data['p'], data['q'])
            return (common.NS(b'ssh-rsa') + common.MP(data['n']) +
                    common.MP(data['e']) + common.MP(data['d']) +
                    common.MP(iqmp) + common.MP(data['p']) +
                    common.MP(data['q']))
        elif type == 'DSA':
            return (common.NS(b'ssh-dss') + common.MP(data['p']) +
                    common.MP(data['q']) + common.MP(data['g']) +
                    common.MP(data['y']) + common.MP(data['x']))
        elif type == 'EC':
            encPub = self._keyObject.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            )
            return (common.NS(data['curve']) + common.NS(data['curve'][-8:]) +
                    common.NS(encPub) + common.MP(data['privateValue']))
        elif type == 'Ed25519':
            return (common.NS(b'ssh-ed25519') + common.NS(data['a']) +
                    common.NS(data['k'] + data['a']))
        else:
            raise BadKeyError('unknown key type: %s' % (force_unicode(type,)))

    def toString(self, type, extra=None, comment=None,
                 passphrase=None):
        """
        Create a string representation of this key.  If the key is a private
        key and you want the representation of its public key, use
        C{key.public().toString()}.  type maps to a _toString_* method.

        @param type: The type of string to emit.  Currently supported values
            are C{'OPENSSH'}, C{'LSH'}, and C{'AGENTV3'}.
        @type type: L{str}

        @param extra: Any extra data supported by the selected format which
            is not part of the key itself.  For public OpenSSH keys, this is
            a comment.  For private OpenSSH keys, this is a passphrase to
            encrypt with.  (Deprecated since Twisted 20.3.0; use C{comment}
            or C{passphrase} as appropriate instead.)
        @type extra: L{bytes} or L{unicode} or L{None}

        @param comment: A comment to include with the key.  Only supported
            for OpenSSH keys.

            Present since Twisted 20.3.0.

        @type comment: L{bytes} or L{unicode} or L{None}

        @param passphrase: A passphrase to encrypt the key with.  Only
            supported for private OpenSSH keys.

            Present since Twisted 20.3.0.

        @type passphrase: L{bytes} or L{unicode} or L{None}

        @rtype: L{bytes}
        """
        if extra is not None:
            if self.isPublic():
                comment = extra
            else:
                passphrase = extra
        if isinstance(comment, unicode):
            comment = comment.encode("utf-8")
        if isinstance(passphrase, unicode):
            passphrase = passphrase.encode("utf-8")
        method = getattr(self, '_toString_%s' % (type.upper(),), None)
        if method is None:
            raise BadKeyError(
                'unknown key type: %s' % (force_unicode(type[:30]),))

        return method(comment=comment, passphrase=passphrase)

    def _toPublicOpenSSH(self, comment=None):
        """
        Return a public OpenSSH key string.

        See _fromString_PUBLIC_OPENSSH for the string format.

        @type comment: L{bytes} or L{None}
        @param comment: A comment to include with the key, or L{None} to
        omit the comment.
        """
        if self.type() == 'EC':
            if not comment:
                comment = b''
            return (self._keyObject.public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH
                ) + b' ' + comment).strip()

        b64Data = encodebytes(self.blob()).replace(b'\n', b'')
        if not comment:
            comment = b''
        return (self.sshType() + b' ' + b64Data + b' ' + comment).strip()

    def _toString_OPENSSH_V1(self, comment=None, passphrase=None):
        """
        Return a private OpenSSH key string, in the "openssh-key-v1" format
        introduced in OpenSSH 6.5.

        See _fromPrivateOpenSSH_v1 for the string format.

        @type passphrase: L{bytes} or L{None}
        @param passphrase: The passphrase to encrypt the key with, or L{None}
        if it is not encrypted.
        """
        if self.isPublic():
            return self._toPublicOpenSSH(comment=comment)

        if passphrase:
            # For now we just hardcode the cipher to the one used by
            # OpenSSH.  We could make this configurable later if it's
            # needed.
            cipher = algorithms.AES
            cipherName = b'aes256-ctr'
            kdfName = b'bcrypt'
            blockSize = cipher.block_size // 8
            keySize = 32
            ivSize = blockSize
            salt = self.secureRandom(ivSize)
            rounds = 100
            kdfOptions = common.NS(salt) + struct.pack('!L', rounds)
        else:
            cipherName = b'none'
            kdfName = b'none'
            blockSize = 8
            kdfOptions = b''
        check = self.secureRandom(4)
        privKeyList = (
            check + check + self.privateBlob() + common.NS(comment or b''))
        padByte = 0
        while len(privKeyList) % blockSize:
            padByte += 1
            privKeyList += chr(padByte & 0xFF)
        if passphrase:
            encKey = bcrypt.kdf(passphrase, salt, keySize + ivSize, 100)
            encryptor = Cipher(
                cipher(encKey[:keySize]),
                modes.CTR(encKey[keySize:keySize + ivSize]),
                backend=default_backend()
            ).encryptor()
            encPrivKeyList = (
                encryptor.update(privKeyList) + encryptor.finalize())
        else:
            encPrivKeyList = privKeyList
        blob = (
            b'openssh-key-v1\0' +
            common.NS(cipherName) +
            common.NS(kdfName) + common.NS(kdfOptions) +
            struct.pack('!L', 1) +
            common.NS(self.blob()) +
            common.NS(encPrivKeyList))
        b64Data = encodebytes(blob).replace(b'\n', b'')
        lines = (
            [b'-----BEGIN OPENSSH PRIVATE KEY-----'] +
            [b64Data[i:i + 64] for i in range(0, len(b64Data), 64)] +
            [b'-----END OPENSSH PRIVATE KEY-----'])
        return b'\n'.join(lines) + b'\n'

    def _toString_OPENSSH(self, comment=None, passphrase=None):
        """
        Return a private OpenSSH key string, in the old PEM-based format.

        See _fromPrivateOpenSSH_PEM for the string format.

        @type passphrase: L{bytes} or L{None}
        @param passphrase: The passphrase to encrypt the key with, or L{None}
        if it is not encrypted.
        """
        if self.isPublic():
            return self._toPublicOpenSSH(comment=comment)

        if self.type() == 'EC':
            # EC keys has complex ASN.1 structure hence we do this this way.
            if not passphrase:
                # unencrypted private key
                encryptor = serialization.NoEncryption()
            else:
                encryptor = serialization.BestAvailableEncryption(passphrase)

            return self._keyObject.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                encryptor)
        elif self.type() == 'Ed25519':
            raise BadKeyError(
                'Cannot serialize Ed25519 key to openssh format; '
                'use openssh_v1 instead.'
            )

        data = self.data()
        lines = [b''.join((b'-----BEGIN ', self.type().encode('ascii'),
                           b' PRIVATE KEY-----'))]
        if self.type() == 'RSA':
            p, q = data['p'], data['q']
            iqmp = rsa.rsa_crt_iqmp(p, q)
            objData = (0, data['n'], data['e'], data['d'], p, q,
                       data['d'] % (p - 1), data['d'] % (q - 1),
                       iqmp)
        else:
            objData = (0, data['p'], data['q'], data['g'], data['y'],
                       data['x'])
        asn1Sequence = univ.Sequence()
        for index, value in izip(itertools.count(), objData):
            asn1Sequence.setComponentByPosition(index, univ.Integer(value))
        asn1Data = berEncoder.encode(asn1Sequence)
        if passphrase:
            iv = self.secureRandom(8)
            hexiv = ''.join(['%02X' % (ord(x),) for x in iterbytes(iv)])
            hexiv = hexiv.encode('ascii')
            lines.append(b'Proc-Type: 4,ENCRYPTED')
            lines.append(b'DEK-Info: DES-EDE3-CBC,' + hexiv + b'\n')
            ba = md5(passphrase + iv).digest()
            bb = md5(ba + passphrase + iv).digest()
            encKey = (ba + bb)[:24]
            padLen = 8 - (len(asn1Data) % 8)
            asn1Data += chr(padLen) * padLen

            encryptor = Cipher(
                algorithms.TripleDES(encKey),
                modes.CBC(iv),
                backend=default_backend()
            ).encryptor()

            asn1Data = encryptor.update(asn1Data) + encryptor.finalize()

        b64Data = encodebytes(asn1Data).replace(b'\n', b'')
        lines += [b64Data[i:i + 64] for i in range(0, len(b64Data), 64)]
        lines.append(b''.join((b'-----END ', self.type().encode('ascii'),
                               b' PRIVATE KEY-----')))
        return b'\n'.join(lines)

    def _toString_LSH(self, **kwargs):
        """
        Return a public or private LSH key.  See _fromString_PUBLIC_LSH and
        _fromString_PRIVATE_LSH for the key formats.

        @rtype: L{bytes}
        """
        data = self.data()
        type = self.type()
        if self.isPublic():
            if type == 'RSA':
                keyData = sexpy.pack([[b'public-key',
                                       [b'rsa-pkcs1-sha1',
                                        [b'n', common.MP(data['n'])[4:]],
                                        [b'e', common.MP(data['e'])[4:]]]]])
            elif type == 'DSA':
                keyData = sexpy.pack([[b'public-key',
                                       [b'dsa',
                                        [b'p', common.MP(data['p'])[4:]],
                                        [b'q', common.MP(data['q'])[4:]],
                                        [b'g', common.MP(data['g'])[4:]],
                                        [b'y', common.MP(data['y'])[4:]]]]])
            else:
                raise BadKeyError(
                    "unknown key type %s" % (force_unicode(type,)))
            return (b'{' + encodebytes(keyData).replace(b'\n', b'') +
                    b'}')
        else:
            if type == 'RSA':
                p, q = data['p'], data['q']
                iqmp = rsa.rsa_crt_iqmp(p, q)
                return sexpy.pack([[b'private-key',
                                    [b'rsa-pkcs1',
                                     [b'n', common.MP(data['n'])[4:]],
                                     [b'e', common.MP(data['e'])[4:]],
                                     [b'd', common.MP(data['d'])[4:]],
                                     [b'p', common.MP(q)[4:]],
                                     [b'q', common.MP(p)[4:]],
                                     [b'a', common.MP(
                                         data['d'] % (q - 1))[4:]],
                                     [b'b', common.MP(
                                         data['d'] % (p - 1))[4:]],
                                     [b'c', common.MP(iqmp)[4:]]]]])
            elif type == 'DSA':
                return sexpy.pack([[b'private-key',
                                    [b'dsa',
                                     [b'p', common.MP(data['p'])[4:]],
                                     [b'q', common.MP(data['q'])[4:]],
                                     [b'g', common.MP(data['g'])[4:]],
                                     [b'y', common.MP(data['y'])[4:]],
                                     [b'x', common.MP(data['x'])[4:]]]]])
            else:
                raise BadKeyError(
                    "unknown key type %s'" % (force_unicode(type,)))

    def _toString_AGENTV3(self, **kwargs):
        """
        Return a private Secure Shell Agent v3 key.  See
        _fromString_AGENTV3 for the key format.

        @rtype: L{bytes}
        """
        data = self.data()
        if not self.isPublic():
            if self.type() == 'RSA':
                values = (data['e'], data['d'], data['n'], data['u'],
                          data['p'], data['q'])
            elif self.type() == 'DSA':
                values = (data['p'], data['q'], data['g'], data['y'],
                          data['x'])
            return common.NS(self.sshType()) + b''.join(map(common.MP, values))

    def sign(self, data):
        """
        Sign some data with this private key.

        SECSH-TRANS RFC 4253 Section 6.6.

        @type data: L{bytes}
        @param data: The data to sign.

        @rtype: L{bytes}
        @return: A signature for the given data.
        """
        if self.isPublic():
            raise KeyCertException('A private key is require to sign data.')

        keyType = self.type()
        if keyType == 'RSA':
            sig = self._keyObject.sign(data, padding.PKCS1v15(), hashes.SHA1())
            ret = common.NS(sig)

        elif keyType == 'DSA':
            sig = self._keyObject.sign(data, hashes.SHA1())
            (r, s) = decode_dss_signature(sig)
            # SSH insists that the DSS signature blob be two 160-bit integers
            # concatenated together. The sig[0], [1] numbers from obj.sign
            # are just numbers, and could be any length from 0 to 160 bits.
            # Make sure they are padded out to 160 bits (20 bytes each)
            ret = common.NS(int_to_bytes(r, 20) + int_to_bytes(s, 20))

        elif keyType == 'EC':  # Pragma: no branch
            # Hash size depends on key size
            keySize = self.size()
            if keySize <= 256:
                hashSize = hashes.SHA256()
            elif keySize <= 384:
                hashSize = hashes.SHA384()
            else:
                hashSize = hashes.SHA512()
            signature = self._keyObject.sign(data, ec.ECDSA(hashSize))
            (r, s) = decode_dss_signature(signature)

            rb = int_to_bytes(r)
            sb = int_to_bytes(s)

            # Int_to_bytes returns rb[0] as a str in python2
            # and an as int in python3
            if type(rb[0]) is str:
                rcomp = ord(rb[0])
            else:
                rcomp = rb[0]

            # If the MSB is set, prepend a null byte for correct formatting.
            if rcomp & 0x80:
                rb = b"\x00" + rb

            if type(sb[0]) is str:
                scomp = ord(sb[0])
            else:
                scomp = sb[0]

            if scomp & 0x80:
                sb = b"\x00" + sb

            ret = common.NS(common.NS(rb) + common.NS(sb))

        elif keyType == 'Ed25519':
            ret = common.NS(self._keyObject.sign(data))
        return common.NS(self.sshType()) + ret

    def verify(self, signature, data):
        """
        Verify a signature using this key.

        @type signature: L{bytes}
        @param signature: The signature to verify.

        @type data: L{bytes}
        @param data: The signed data.

        @rtype: L{bool}
        @return: C{True} if the signature is valid.
        """
        if len(signature) == 40:
            # DSA key with no padding
            signatureType, signature = b'ssh-dss', common.NS(signature)
        else:
            signatureType, signature = common.getNS(signature)

        if signatureType != self.sshType():
            return False

        keyType = self.type()
        if keyType == 'RSA':
            k = self._keyObject
            if not self.isPublic():
                k = k.public_key()
            args = (
                common.getNS(signature)[0],
                data,
                padding.PKCS1v15(),
                hashes.SHA1(),
            )
        elif keyType == 'DSA':
            concatenatedSignature = common.getNS(signature)[0]
            r = int_from_bytes(concatenatedSignature[:20], 'big')
            s = int_from_bytes(concatenatedSignature[20:], 'big')
            signature = encode_dss_signature(r, s)
            k = self._keyObject
            if not self.isPublic():
                k = k.public_key()
            args = (signature, data, hashes.SHA1())

        elif keyType == 'EC':  # Pragma: no branch
            concatenatedSignature = common.getNS(signature)[0]
            rstr, sstr, rest = common.getNS(concatenatedSignature, 2)
            r = int_from_bytes(rstr, 'big')
            s = int_from_bytes(sstr, 'big')
            signature = encode_dss_signature(r, s)

            k = self._keyObject
            if not self.isPublic():
                k = k.public_key()

            keySize = self.size()
            if keySize <= 256:  # Hash size depends on key size
                hashSize = hashes.SHA256()
            elif keySize <= 384:
                hashSize = hashes.SHA384()
            else:
                hashSize = hashes.SHA512()
            args = (signature, data, ec.ECDSA(hashSize))

        elif keyType == 'Ed25519':
            k = self._keyObject
            if not self.isPublic():
                k = k.public_key()
            args = (common.getNS(signature)[0], data)

        try:
            k.verify(*args)
        except InvalidSignature:
            return False
        else:
            return True

    @staticmethod
    def secureRandom(n):  # pragma: no cover
        return urandom(n)

    @classmethod
    def generate(cls, key_type=DEFAULT_KEY_TYPE, key_size=None):
        """
        Return a new private key.

        When `key_size` is None, the default value is used.

        `key_size` is ignored for ed25519.
        """
        if not key_type:
            key_type = 'not-specified'
        key_type = key_type.lower()

        if not key_size:
            if key_type == 'ecdsa':
                key_size = 384
            else:
                key_size = DEFAULT_KEY_SIZE

        key = None
        try:
            if key_type == u'rsa':
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                    )
            elif key_type == u'dsa':
                key = dsa.generate_private_key(key_size=key_size)
            elif key_type == 'ecdsa':
                try:
                    curve = _ecSizeTable[key_size]
                except KeyError:
                    raise KeyCertException(
                        'Wrong key size "%s". Supported: %s.' % (
                            key_size,
                            ', '.join([str(s) for s in _ecSizeTable.keys()])))
                key = ec.generate_private_key(curve)
            elif key_type == 'ed25519':
                key = ed25519.Ed25519PrivateKey.generate()
            else:
                raise KeyCertException('Unknown key type "%s".' % (key_type))

        except ValueError as error:
            raise KeyCertException(
                u'Wrong key size "%d". %s' % (key_size, error))

        return cls(key)


    @classmethod
    def getKeyFormat(cls, data):
        """
        Return a type of key.
        """
        key_type = cls._guessStringType(data)
        human_readable = {
            'public_openssh': 'OpenSSH Public',
            'private_openssh': 'OpenSSH Private old format',
            'private_openssh_v1': 'OpenSSH Private new format',
            'public_sshcom': 'SSH.com Public',
            'private_sshcom': 'SSH.com Private',
            'private_putty': 'PuTTY Private',
            'public_lsh': 'LSH Public',
            'private_lsh': 'LSH Private',
            'public_x509_certificate': 'X509 Certificate',
            'public_x509': 'X509 Public',
            'public_pkcs1_rsa': 'PKCS#1 RSA Public',
            'private_pkcs8': 'PKCS#8 Private',
            'private_encrypted_pkcs8': 'PKCS#8 Encrypted Private',
            }

        return human_readable.get(key_type, 'Unknown format')

    @staticmethod
    def _getSSHCOMKeyContent(data):
        """
        Return the raw content of the SSH.com key (private or public) without
        armor and headers.
        """
        lines = data.strip().splitlines()
        # Split in lines, ignoring the first and last armors.
        lines = lines[1:-1]

        # Filter headers, first line without ':' and which is not a
        # continuation is the first line of the headers
        continuation = False
        while True:
            if not lines:
                # End of content.
                break

            line = lines.pop(0)
            if continuation:
                # We have a continued line.
                # ignore it and check if this line still continues.
                if not line.endswith('\\'):
                    continuation = False
                continue

            if ':' in line:
                # We have a header line
                # Ignore it and check if this is a long header.
                if line.endswith('\\'):
                    continuation = True
                continue
            # This is not a header and not a continuation, so it must be the
            # first line form content.
            # Put it back and stop filtering the content.
            lines.insert(0, line)
            break

        content = ''.join(lines)
        return base64.decodestring(content)

    @classmethod
    def _fromString_PUBLIC_SSHCOM(cls, data):
        """
        Return a public key object corresponding to this SSH.com public key
        string.  The format of a SSH.com public key string is::
            ---- BEGIN SSH2 PUBLIC KEY ----
            Subject: KEY_SUBJECT_UTF8
            Comment: KEY_COMMENT_UTF8 \
            KEY_COMMEMENT_CONTINUATION
            x-private-headder: VALUE_UTF8
            <base64-encoded public key blob wrapped on lines at maximum 72>
            ---- END SSH2 PUBLIC KEY ----

        * SSH.com content is wrapped at 70. putty-gen wraps it at 64.
        * Header-tag MUST NOT be more than 64 8-bit bytes and is
          case-insensitive.
        * The Header-value MUST NOT be more than 1024 8-bit bytes.
        * Each line in the header MUST NOT be more than 72 8-bit bytes.
        * A line is continued if the last character in the line is a '\'.
        * The Header-tag MUST be encoded in US-ASCII.
        * The Header-value MUST be encoded in UTF-8

        Compliant implementations MUST ignore headers with unrecognized
        header-tags.  Implementations SHOULD preserve such unrecognized
        headers when manipulating the key file.

        @type data: C{bytes}
        @return: A {Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if the blob type is unknown.
        """
        if not data.strip().endswith('---- END SSH2 PUBLIC KEY ----'):
            raise BadKeyError("Fail to find END tag for SSH.com key.")

        blob = cls._getSSHCOMKeyContent(data)
        return cls._fromString_BLOB(blob)

    @classmethod
    def _fromString_PRIVATE_SSHCOM(cls, data, passphrase):
        """
        Return a private key object corresponding to this SSH.com private key
        string.

        See: L{_fromString_PUBLIC_SSH2} for information about key format.

        Key content is in PKCS#8 RFC 5208 Base64 encoded,
        wrapped at maximum 72.

        SSH.com and putty-gen wraps the key at 70.

        Blob format as documented in Putty/import.c:
        *  uint32 magic number
        *  uint32 total blob size
        *  string key-type
        *  string cipher-type      (tells you if key is encrypted)
        *  string encrypted-blob

        Key types:
        * RSA if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}
        * DSA dl-modp{sign{dsa-nist-sha1},dh{plain}}

        Encryption key:
        *  first 16 bytes are MD5(passphrase)
        *  next 16 bytes are MD5(passphrase || first 16 bytes)
        *  concatenate at 24

        The payload for an RSA key:
        * mpint e
        * mpint d
        * mpint n
        * mpint u
        * mpint p
        * mpint q

        The payload for a DSA key:
        * uint32 0
        * mpint p
        * mpint g
        * mpint q
        * mpint y
        * mpint x

        @type data: C{bytes}
        @return: A {Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if
            * the blob type is unknown.
            * a passphrase is provided for an unencrypted key
        """
        blob = cls._getSSHCOMKeyContent(data)
        magic_number = struct.unpack('>I', blob[:4])[0]
        if magic_number != SSHCOM_MAGIC_NUMBER:
            raise BadKeyError(
                'Bad magic number for SSH.com key %r' % (
                    force_unicode(magic_number),))
        struct.unpack('>I', blob[4:8])[0]  # Ignore value for total size.
        type_signature, rest = common.getNS(blob[8:])

        key_type = None
        if type_signature.startswith('if-modn{sign{rsa'):
            key_type = 'rsa'
        elif type_signature.startswith('dl-modp{sign{dsa'):
            key_type = 'dsa'
        else:
            raise BadKeyError(
                'Unknown SSH.com key type %s' % force_unicode(type_signature))

        cipher_type, rest = common.getNS(rest)
        encrypted_blob, _ = common.getNS(rest)

        encryption_key = None
        if cipher_type.lower() == b'none':
            if passphrase:
                raise BadKeyError('SSH.com key not encrypted')
            key_data = encrypted_blob
        elif cipher_type.lower() == b'3des-cbc':
            if not passphrase:
                raise EncryptedKeyError(
                    'Passphrase must be provided for an encrypted key.')
            encryption_key = cls._getDES3EncryptionKey(passphrase)
            decryptor = Cipher(
                algorithms.TripleDES(encryption_key),
                modes.CBC(b'\x00' * 8),
                backend=default_backend()
            ).decryptor()
            key_data = decryptor.update(encrypted_blob) + decryptor.finalize()
        else:
            raise BadKeyError(
                'Encryption method not supported: %r' % (
                    force_unicode(cipher_type[:30])))

        try:
            payload, _ = common.getNS(key_data)
            if key_type == 'rsa':
                e, d, n, u, p, q, rest = cls._unpackMPSSHCOM(payload, 6)
                return cls._fromRSAComponents(n=n, e=e, d=d, p=p, q=q, u=u)

            if key_type == 'dsa':
                # First 32bit is an uint with value 0. We just ignore it.
                p, g, q, y, x, rest = cls._unpackMPSSHCOM(payload[4:], 5)
                return cls._fromDSAComponents(y=y, g=g, p=p, q=q, x=x)
        except struct.error:
            if encryption_key:
                raise EncryptedKeyError('Bad password or bad key format.')
            else:
                BadKeyError('Failed to parse payload.')

    @staticmethod
    def _getDES3EncryptionKey(passphrase):
        """
        Return the encryption key used in DES3 cypher.
        """
        DES3_KEY_SIZE = 24
        pass_1 = md5(passphrase).digest()
        pass_2 = md5(passphrase + pass_1).digest()
        return (pass_1 + pass_2)[:DES3_KEY_SIZE]

    @staticmethod
    def _unpackMPSSHCOM(data, count=1):
        """
        Get SSHCOM mpint.

        32-bit bit count N, followed by (N+7)/8 bytes of data.

        Similar to Twisted getMP method.
        """
        c = 0
        mp = []
        for i in range(count):
            length = struct.unpack('>I', data[c:c + 4])[0]
            length = (length + 7) // 8
            mp.append(int_from_bytes(data[c + 4:c + 4 + length], 'big'))
            c += length + 4
        return tuple(mp) + (data[c:],)

    @staticmethod
    def _packMPSSHCOM(number):
        """
        Return the wire representation of a MP number for SSH.com.

        Similar to Twisted MP method.
        """
        if number == 0:
            return '\000' * 4

        wire_number = int_to_bytes(number)

        wire_length = (len(wire_number) * 8) - 7
        return struct.pack('>L', wire_length) + wire_number

    def _toString_SSHCOM(self, comment=None, passphrase=None):
        """
        Return a public or private SSH.com string.

        See _fromString_PUBLIC_SSHCOM and _fromString_PRIVATE_SSHCOM for the
        string formats.  If extra is present, it represents a comment for a
        public key, or a passphrase for a private key.

        @param extra: Comment for a public key or passphrase for a private key.
        @type extra: C{bytes}

        @rtype: C{bytes}
        """
        if self.isPublic():
            return self._toString_SSHCOM_public(comment)
        else:
            return self._toString_SSHCOM_private(passphrase)

    def _toString_SSHCOM_public(self, extra):
        """
        Return the public SSH.com string.
        """
        lines = ['---- BEGIN SSH2 PUBLIC KEY ----']
        if extra:
            line = 'Comment: "%s"' % (extra.encode('utf-8'),)
            lines.append('\\\n'.join(textwrap.wrap(line, 70)))

        base64Data = base64.b64encode(self.blob())
        lines.extend(textwrap.wrap(base64Data, 70))
        lines.append('---- END SSH2 PUBLIC KEY ----')
        return '\n'.join(lines)

    def _toString_SSHCOM_private(self, extra):
        """
        Return the private SSH.com string.
        """
        # Now we are left with a private key.
        # Both encrypted and unencrypted keys have the same armor.
        lines = ['---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----']

        type_signature = None
        payload_blob = None
        data = self.data()
        type = self.type()
        if type == 'RSA':
            type_signature = (
                'if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}')
            payload_blob = (
                self._packMPSSHCOM(data['e']) +
                self._packMPSSHCOM(data['d']) +
                self._packMPSSHCOM(data['n']) +
                self._packMPSSHCOM(data['u']) +
                self._packMPSSHCOM(data['p']) +
                self._packMPSSHCOM(data['q'])
                )
        elif type == 'DSA':
            type_signature = 'dl-modp{sign{dsa-nist-sha1},dh{plain}}'
            payload_blob = (
                struct.pack('>I', 0) +
                self._packMPSSHCOM(data['p']) +
                self._packMPSSHCOM(data['g']) +
                self._packMPSSHCOM(data['q']) +
                self._packMPSSHCOM(data['y']) +
                self._packMPSSHCOM(data['x'])
                )
        else:  # pragma: no cover
            raise BadKeyError('Unsupported key type %s' % force_unicode(type))

        payload_blob = common.NS(payload_blob)

        if extra:
            # We got a password, so encrypt it.
            cipher_type = '3des-cbc'
            padding = b'\x00' * (8 - (len(payload_blob) % 8))
            payload_blob = payload_blob + padding
            encryption_key = self._getDES3EncryptionKey(extra)

            encryptor = Cipher(
                algorithms.TripleDES(encryption_key),
                modes.CBC(b'\x00' * 8),
                backend=default_backend()
            ).encryptor()
            encrypted_blob = (
                encryptor.update(payload_blob) + encryptor.finalize())
        else:
            cipher_type = 'none'
            encrypted_blob = payload_blob

        # We first create the content without magic number and
        # total size, then compute the total size, and update the
        # final content.
        blob = (
            common.NS(type_signature)
            + common.NS(cipher_type)
            + common.NS(encrypted_blob)
            )
        total_size = 8 + len(blob)
        blob = (
            struct.pack('>I', SSHCOM_MAGIC_NUMBER)
            + struct.pack('>I', total_size)
            + blob
            )

        # In the end, encode in base 64 and wrap it.
        blob = base64.b64encode(blob)
        lines.extend(textwrap.wrap(blob, 70))

        lines.append('---- END SSH2 ENCRYPTED PRIVATE KEY ----')
        return '\n'.join(lines).encode('ascii')

    @classmethod
    def _fromString_PRIVATE_PUTTY(cls, data, passphrase):
        """
        Read a private Putty key.

        Format is:

        PuTTY-User-Key-File-2: ssh-rsa
        Encryption: aes256-cbc | none
        Comment: SINGLE_LINE_COMMENT
        Public-Lines: PUBLIC_LINES
        < base64 public part always in plain >
        Private-Lines: 8
        < base64 private part >
        Private-MAC: 1398fbfc7ce307d9ee0e42851f183f88c728398f

        Pulic part RSA:
        * string type (ssh-rsa)
        * mpint e
        * mpint n
        Private part RSA:
        * mpint d
        * mpint q
        * mpint p
        * mpint u

        Pulic part DSA:
        * string type (ssh-dss)
        * mpint p
        * mpint q
        * mpint g
        * mpint v`
        Private part DSA:
        * mpint x

        Public part ECDSA-SHA2-*:
        * string 'ecdsa-sha2-[identifier]'
        * string identifier
        * mpint x
        * mpint y
        Private part ECDSA-SHA2-*:
        * string q
        * mpint privateValue

        Public part Ed25519:
        * string type (ssh-ed25519)
        * string a
        Private part Ed25519:
        * string k

        Private part is padded for encryption.

        Encryption key is composed of concatenating, up to block size:
        * uint32 sequence, starting from 0
        * passphrase

        Lines are terminated by CRLF, although CR-only and LF-only are
        tolerated on input.

        Only version 2 is supported.
        Version 2 was introduced in PuTTY 0.52.
        Version 1 was an in-development format used in 0.52 snapshot
        """
        lines = data.strip().splitlines()

        key_type = lines[0][22:].strip().lower()
        if key_type not in [
            b'ssh-rsa',
            b'ssh-dss',
            b'ssh-ed25519',
                ] and key_type not in _curveTable:
            raise BadKeyError(
                'Unsupported key type: %r' % force_unicode(key_type[:30]))

        encryption_type = lines[1][11:].strip().lower()

        if encryption_type == b'none':
            if passphrase:
                raise BadKeyError('PuTTY key not encrypted')
        elif encryption_type != b'aes256-cbc':
            raise BadKeyError(
                'Unsupported encryption type: %r' % force_unicode(
                    encryption_type[:30]))

        comment = lines[2][9:].strip()

        public_count = int(lines[3][14:].strip())
        base64_content = ''.join(lines[
            4:
            4 + public_count
            ])
        public_blob = base64.decodestring(base64_content)
        public_type, public_payload = common.getNS(public_blob)

        if public_type.lower() != key_type:
            raise BadKeyError(
                'Mismatch key type. Header has %r, public has %r' % (
                    force_unicode(key_type[:30]),
                    force_unicode(public_type[:30])))

        # We skip 4 lines so far and the total public lines.
        private_start_line = 4 + public_count
        private_count = int(lines[private_start_line][15:].strip())
        base64_content = ''.join(lines[
            private_start_line + 1:
            private_start_line + 1 + private_count
            ])
        private_blob = base64.decodestring(base64_content)

        private_mac = lines[-1][12:].strip()

        hmac_key = PUTTY_HMAC_KEY
        encryption_key = None
        if encryption_type == b'aes256-cbc':
            if not passphrase:
                raise EncryptedKeyError(
                    'Passphrase must be provided for an encrypted key.')
            hmac_key += passphrase
            encryption_key = cls._getPuttyAES256EncryptionKey(passphrase)
            decryptor = Cipher(
                algorithms.AES(encryption_key),
                modes.CBC(b'\x00' * 16),
                backend=default_backend()
            ).decryptor()
            private_blob = (
                decryptor.update(private_blob) + decryptor.finalize())

        # I have no idea why these values are packed form HMAC as net strings.
        hmac_data = (
            common.NS(key_type) +
            common.NS(encryption_type) +
            common.NS(comment) +
            common.NS(public_blob) +
            common.NS(private_blob)
            )
        hmac_key = sha1(hmac_key).digest()
        computed_mac = hmac.new(hmac_key, hmac_data, sha1).hexdigest()
        if private_mac != computed_mac:
            if encryption_key:
                raise EncryptedKeyError('Bad password or HMAC mismatch.')
            else:
                raise BadKeyError(
                    'HMAC mismatch: file declare %s, actual is %s' % (
                        force_unicode(private_mac),
                        force_unicode(computed_mac)))

        if key_type == b'ssh-rsa':
            e, n, _ = common.getMP(public_payload, count=2)
            d, q, p, u, _ = common.getMP(private_blob, count=4)
            return cls._fromRSAComponents(n=n, e=e, d=d, p=p, q=q, u=u)

        if key_type == b'ssh-dss':
            p, q, g, y, _ = common.getMP(public_payload, count=4)
            x, _ = common.getMP(private_blob)
            return cls._fromDSAComponents(y=y, g=g, p=p, q=q, x=x)

        if key_type == b'ssh-ed25519':
            a, _ = common.getNS(public_payload)
            k, _ = common.getNS(private_blob)
            return cls._fromEd25519Components(a=a, k=k)

        if key_type in _curveTable:
            curve = _curveTable[key_type]
            curveName, q, _ = common.getNS(public_payload, 2)
            if curveName != _secToNist[curve.name.encode('ascii')]:
                raise BadKeyError(
                    'ECDSA curve name %r does not match key type %r' % (
                        force_unicode(curveName),
                        force_unicode(key_type)))

            privateValue, _ = common.getMP(private_blob)
            return cls._fromECEncodedPoint(
                encodedPoint=q, curve=key_type, privateValue=privateValue)

    @staticmethod
    def _getPuttyAES256EncryptionKey(passphrase):
        """
        Return the encryption key used in Putty AES 256 cipher.
        """
        key_size = 32
        part_1 = sha1(b'\x00\x00\x00\x00' + passphrase).digest()
        part_2 = sha1(b'\x00\x00\x00\x01' + passphrase).digest()
        return (part_1 + part_2)[:key_size]

    def _toString_PUTTY(self, comment=None, passphrase=None):
        """
        Return a public or private Putty string.

        See _fromString_PRIVATE_PUTTY for the private format.
        See _fromString_PUBLIC_SSHCOM for the public format.

        Private key is exported in version 2 format.

        If extra is present, it represents a comment for a
        public key, or a passphrase for a private key.

        @param extra: Comment for a public key or passphrase for a private key.
        @type extra: C{bytes}

        @rtype: C{bytes}
        """
        if self.isPublic():
            # Putty uses SSH.com as public format.
            return self._toString_SSHCOM_public(comment)
        else:
            return self._toString_PUTTY_private(passphrase)

    def _toString_PUTTY_private(self, extra):
        """
        Return the Putty private key representation.

        See fromString for Putty file format.
        """
        aes_block_size = 16
        lines = []
        key_type = self.sshType()
        comment = 'Exported by chevah-keycert.'
        data = self.data()

        hmac_key = PUTTY_HMAC_KEY
        if extra:
            encryption_type = b'aes256-cbc'
            hmac_key += extra
        else:
            encryption_type = 'none'

        if key_type == b'ssh-rsa':
            public_blob = (
                common.NS(key_type) +
                common.MP(data['e']) +
                common.MP(data['n'])
                )
            private_blob = (
                common.MP(data['d']) +
                common.MP(data['q']) +
                common.MP(data['p']) +
                common.MP(data['u'])
                )
        elif key_type == b'ssh-dss':
            public_blob = (
                common.NS(key_type) +
                common.MP(data['p']) +
                common.MP(data['q']) +
                common.MP(data['g']) +
                common.MP(data['y'])
                )
            private_blob = common.MP(data['x'])

        elif key_type == b'ssh-ed25519':
            public_blob = (
                common.NS(key_type) +
                common.NS(data['a'])
                )
            private_blob = common.NS(data['k'])

        elif key_type in _curveTable:

            curve_name = _secToNist[self._keyObject.curve.name]
            public_blob = (
                common.NS(key_type) +
                common.NS(curve_name) +
                common.NS(self._keyObject.public_key().public_numbers().encode_point())
                )
            private_blob = common.MP(data['privateValue'])

        else:  # pragma: no cover
            raise BadKeyError('Unsupported key type.')

        private_blob_plain = private_blob
        private_blob_encrypted = private_blob

        if extra:
            # Encryption is requested.
            # Padding is required for encryption.
            padding_size = -1 * (
                (len(private_blob) % aes_block_size) - aes_block_size)
            private_blob_plain += b'\x00' * padding_size
            encryption_key = self._getPuttyAES256EncryptionKey(extra)
            encryptor = Cipher(
                algorithms.AES(encryption_key),
                modes.CBC(b'\x00' * aes_block_size),
                backend=default_backend()
            ).encryptor()
            private_blob_encrypted = (
                encryptor.update(private_blob_plain) + encryptor.finalize())

        public_lines = textwrap.wrap(base64.b64encode(public_blob), 64)
        private_lines = textwrap.wrap(
            base64.b64encode(private_blob_encrypted), 64)

        hmac_data = (
            common.NS(key_type) +
            common.NS(encryption_type) +
            common.NS(comment) +
            common.NS(public_blob) +
            common.NS(private_blob_plain)
            )
        hmac_key = sha1(hmac_key).digest()
        private_mac = hmac.new(hmac_key, hmac_data, sha1).hexdigest()

        lines.append('PuTTY-User-Key-File-2: %s' % key_type)
        lines.append('Encryption: %s' % encryption_type)
        lines.append('Comment: %s' % comment)
        lines.append('Public-Lines: %s' % len(public_lines))
        lines.extend(public_lines)
        lines.append('Private-Lines: %s' % len(private_lines))
        lines.extend(private_lines)
        lines.append('Private-MAC: %s' % private_mac)
        return '\r\n'.join(lines)

    @classmethod
    def _fromString_PUBLIC_X509_CERTIFICATE(cls, data):
        """
        Read the public key from X509 Certificates in PEM format.
        """
        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        except crypto.Error as error:
            raise BadKeyError(
                'Failed to load certificate. %s' % (force_unicode(error),))

        return cls._fromOpenSSLPublic(cert.get_pubkey(), 'certificate')

    @classmethod
    def _fromString_PUBLIC_X509(cls, data):
        """
        Read the public key from X509 public key PEM format.
        """
        try:
            pkey = crypto.load_publickey(crypto.FILETYPE_PEM, data)
        except crypto.Error as error:
            raise BadKeyError(
                'Failed to load PKCS#1 public key. %s' % (
                    force_unicode(error),))

        return cls._fromOpenSSLPublic(pkey, 'X509 public PEM file')

    @classmethod
    def _fromOpenSSLPublic(cls, pkey, source_type):
        """
        Load the SSH from an OpenSSL Public Key object.
        """
        return cls(pkey.to_cryptography_key())

    @classmethod
    def _fromString_PRIVATE_PKCS8(cls, data, passphrase=None):
        """
        Read the private key from PKCS8 PEM format.
        """
        return cls._load_PRIVATE_PKCS8(data, passphrase='')

    @classmethod
    def _fromString_PRIVATE_ENCRYPTED_PKCS8(cls, data, passphrase=None):
        """
        Read the encrypted private key from PKCS8 PEM format.
        """
        if not passphrase:
            raise EncryptedKeyError(
                'Passphrase must be provided for an encrypted key')

        return cls._load_PRIVATE_PKCS8(data, passphrase)

    @classmethod
    def _load_PRIVATE_PKCS8(cls, data, passphrase):
        """
        Shared code for loading a private PKCS8 key.
        """
        try:
            key = crypto.load_privatekey(
                crypto.FILETYPE_PEM, data, passphrase=passphrase)
        except crypto.Error as error:
            raise BadKeyError(
                'Failed to load PKCS#8 PEM. %s' % (force_unicode(error),))

        return cls(key.to_cryptography_key())

    @classmethod
    def _fromString_PUBLIC_PKCS1_RSA(cls, data):
        """
        Read the public key from PKCS1 PEM format.

        This is also the OpenSSH public PEM.

        RSAPublicKey ::= SEQUENCE {
            modulus           INTEGER,  -- n
            publicExponent    INTEGER   -- e
            }

        """
        lines = data.strip().splitlines()
        data = base64.decodestring(b''.join(lines[1:-1]))
        decodedKey = berDecoder.decode(data)[0]
        if len(decodedKey) != 2:
            raise BadKeyError('Invalid ASN.1 payload for PKCS1 PEM.')

        n = long(decodedKey[0])
        e = long(decodedKey[1])
        return cls._fromRSAComponents(n=n, e=e)


def generate_ssh_key_parser(subparsers, name, default_key_type='rsa'):
    """
    Create an argparse sub-command with `name` attached to `subparsers`.
    """
    generate_ssh_key = subparsers.add_parser(
        name,
        help='Create a SSH public and private key pair.',
        )
    generate_ssh_key.add_argument(
        '--key-file',
        metavar='FILE',
        help=(
            'Store the keys pair in FILE and FILE.pub. Default id_TYPE.'),
        )
    generate_ssh_key.add_argument(
        '--key-size',
        type=int, metavar="SIZE", default=None,
        help='Generate a SSH key of size SIZE',
        )
    generate_ssh_key.add_argument(
        '--key-type',
        metavar="[rsa|dsa|ecdsa|ed25519]", default=default_key_type,
        help='Generate a new SSH private and public key. Default %(default)s.',
        )
    generate_ssh_key.add_argument(
        '--key-comment',
        metavar="COMMENT_TEXT",
        help=(
            'Generate the public key using this comment. Default no comment.'),
        )
    generate_ssh_key.add_argument(
        '--key-format',
        metavar="[openssh|openssh_v1|putty]", default='openssh_v1',
        help='Generate a new SSH private and public key. Default %(default)s.',
        )
    generate_ssh_key.add_argument(
        '--key-password',
        metavar="PLAIN-PASS", default=None,
        help='Password used to store the SSH private key.',
        )
    generate_ssh_key.add_argument(
        '--key-skip',
        action='store_true', default=False,
        help='Do not create a new key if a key file already exists.',
        )
    return generate_ssh_key


def generate_ssh_key(options, open_method=None):
    """
    Generate a SSH RSA or DSA key and store it on disk.

    `options` is an argparse namespace. See `generate_ssh_key_subparser`.

    Return a tuple of (exit_code, operation_message, key).

    For success, exit_code is 0.

    `open_method` is a helper for dependency injection during tests.
    """
    key = None

    if open_method is None:  # pragma: no cover
        open_method = open

    exit_code = 0
    message = ''
    try:
        key_size = options.key_size
        key_type = options.key_type.lower()
        key_format = options.key_format.lower()

        if not hasattr(options, 'key_file') or options.key_file is None:
            options.key_file = u'id_%s' % (key_type)

        private_file = options.key_file

        public_file = u'%s%s' % (
            options.key_file, DEFAULT_PUBLIC_KEY_EXTENSION)

        skip = _skip_key_generation(options, private_file, public_file)
        if skip:
            return (0, u'Key already exists.', key)

        key = Key.generate(key_type=key_type, key_size=key_size)

        with open_method(_path(private_file), 'wb') as file_handler:
            _store_SSHKey(
                key,
                private_file=file_handler,
                key_format=key_format,
                password=options.key_password,
                )

        key_comment = None
        if hasattr(options, 'key_comment') and options.key_comment:
            key_comment = options.key_comment
            message_comment = u'having comment "%s"' % key_comment
            if key_format != 'openssh':
                key_comment = None
                message_comment = (
                    'without comment as not supported by the output format')
        else:
            message_comment = u'without a comment'

        with open_method(_path(public_file), 'wb') as file_handler:
            _store_SSHKey(
                key,
                public_file=file_handler,
                comment=key_comment,
                key_format=key_format,
                )

        message = (
            u'SSH key of type "%s" and length "%d" generated as '
            u'public key file "%s" and private key file "%s" %s.') % (
            key.sshType(),
            key.size(),
            public_file,
            private_file,
            message_comment,
            )

        exit_code = 0

    except KeyCertException as error:
        exit_code = 1
        message = error.message
    except Exception as error:
        exit_code = 1
        message = unicode(error)

    return (exit_code, message, key)


def _store_SSHKey(
    key,
    public_file=None, private_file=None,
    comment=None, password=None, key_format='openssh_v1',
        ):
    """
    Store the public and private key into a file like object using
    OpenSSH format.
    """
    if public_file:
        public_serialization = key.public().toString(
            type=key_format)
        if comment:
            public_content = '%s %s' % (
                public_serialization, comment.encode('utf-8'))
        else:
            public_content = public_serialization
        public_file.write(public_content)

    if private_file:
        private_file.write(key.toString(type=key_format, passphrase=password))


def _skip_key_generation(options, private_file, public_file):
    """
    Return True when key generation can be skipped.

    Key generation can be skipped when private key already exists. Public
    key is ignored.

    Raise KeyCertException if file exists.
    """
    if os.path.exists(_path(private_file)):
        if options.key_skip:
            return True
        else:
            raise KeyCertException(
                u'Private key already exists. %s' % private_file)

    if os.path.exists(_path(public_file)):
        raise KeyCertException(u'Public key already exists. %s' % public_file)
    return False
