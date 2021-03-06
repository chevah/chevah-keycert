# Copyright (c) 2014 Adi Roiban.
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
SSH keys management.
"""

from __future__ import absolute_import, division
import base64
import binascii
import hmac
import itertools
import struct
import textwrap
import os.path
from hashlib import md5, sha1, sha256
from os import urandom

from Crypto import Util
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import DSA, RSA
from OpenSSL import crypto
from pyasn1.codec.ber import decoder as berDecoder
from pyasn1.codec.ber import encoder as berEncoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ
from constantly import Names, NamedConstant


from chevah.keycert import common, sexpy, _path
from chevah.keycert.common import (
    long,
    iterbytes,
    izip,
    native_string,
    )
from chevah.keycert.exceptions import (
    BadKeyError,
    EncryptedKeyError,
    KeyCertException,
    )


DEFAULT_PUBLIC_KEY_EXTENSION = u'.pub'
DEFAULT_KEY_SIZE = 1024
DEFAULT_KEY_TYPE = 'rsa'
SSHCOM_MAGIC_NUMBER = int('3f6ff9eb', base=16)
PUTTY_HMAC_KEY = 'putty-private-key-file-mac-key'
ID_SHA1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'


def generate_ssh_key_parser(
        subparsers, name, default_key_size=2048, default_key_type='rsa'):
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
        type=int, metavar="SIZE", default=default_key_size,
        help='Generate a RSA or DSA key of size SIZE. Default %(default)s',
        )
    generate_ssh_key.add_argument(
        '--key-type',
        metavar="[rsa|dsa]", default=default_key_type,
        help='Generate a DSA or RSA key. Default %(default)s.',
        )
    generate_ssh_key.add_argument(
        '--key-comment',
        metavar="COMMENT_TEXT",
        help=(
            'Generate the public key using this comment. Default no comment.'),
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
            _store_OpenSSH(key, private_file=file_handler)

        key_comment = None
        if hasattr(options, 'key_comment') and options.key_comment:
            key_comment = options.key_comment
            message_comment = u'having comment "%s"' % key_comment
        else:
            message_comment = u'without a comment'

        with open_method(_path(public_file), 'wb') as file_handler:
            _store_OpenSSH(key, public_file=file_handler, comment=key_comment)

        message = (
            u'SSH key of type "%s" and length "%d" generated as '
            u'public key file "%s" and private key file "%s" %s.') % (
            key_type,
            key_size,
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
        message = str(error)

    return (exit_code, message, key)


def _store_OpenSSH(key, public_file=None, private_file=None, comment=None):
    """
    Store the public and private key into a file like object using
    OpenSSH format.
    """
    if public_file:
        public_openssh = key.public().toString(type='openssh')
        if comment:
            public_content = '%s %s' % (
                public_openssh, comment.encode('utf-8'))
        else:
            public_content = public_openssh
        public_file.write(public_content)

    if private_file:
        private_file.write(key.toString(type='openssh'))


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


class BadFingerPrintFormat(Exception):
    """
    Raises when unsupported fingerprint formats are presented to fingerprint.
    """


class FingerprintFormats(Names):
    """
    Constants representing the supported formats of key fingerprints.

    @cvar MD5_HEX: Named constant representing fingerprint format generated
        using md5[RFC1321] algorithm in hexadecimal encoding.
    @type MD5_HEX: L{NamedConstant}

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


class Key(object):
    """
    An object representing a key.  A key can be either a public or
    private key.  A public key can verify a signature; a private key can
    create or verify a signature.  To generate a string that can be stored
    on disk, use the toString method.  If you have a private key, but want
    the string representation of the public key, use Key.public().toString().

    @ivar keyObject: The C{Crypto.PublicKey.pubkey.pubkey} object that
        operations are performed with.
    """

    @staticmethod
    def secureRandom(n):  # pragma: no cover
        return urandom(n)

    def __init__(self, keyObject):
        """
        Initialize a PublicKey with a C{Crypto.PublicKey.pubkey.pubkey}
        object.

        @type keyObject: C{Crypto.PublicKey.pubkey.pubkey}
        """
        self.keyObject = keyObject

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
        lines = [
            '<%s %s (%s bits)' % (
                native_string(self.type()),
                self.isPublic() and 'Public Key' or 'Private Key',
                self.keyObject.size())]
        for k, v in sorted(self.data().items()):
            lines.append('attr %s:' % k)
            by = common.MP(v)[4:]
            while by:
                m = by[:15]
                by = by[15:]
                o = ''
                for c in iterbytes(m):
                    o = o + '%02x:' % ord(c)
                if len(m) < 15:
                    o = o[:-1]
                lines.append('\t' + o)
        lines[-1] = lines[-1] + '>'
        return '\n'.join(lines)

    @classmethod
    def fromFile(cls, filename, type=None, passphrase=None, encoding='utf-8'):
        """
        Return a Key object corresponding to the data in filename.  type
        and passphrase function as they do in fromString.
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

        @type data: C{bytes}
        @type type: C{None}/C{bytes}
        @type passphrase: C{None}/C{bytes}
        @rtype: C{Key}
        """
        if type is None:
            type = cls._guessStringType(data)
        if type is None:
            raise BadKeyError('Cannot guess the type for %r' % data[:80])

        try:
            method = getattr(cls, '_fromString_%s' % type.upper(), None)
            if method is None:
                raise BadKeyError('no _fromString method for %r' % type[:30])
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

    def toString(self, type, extra=None):
        """
        Create a string representation of this key.  If the key is a private
        key and you want the represenation of its public key, use
        C{key.public().toString()}.  type maps to a _toString_* method.

        @param type: The type of string to emit.  Currently supported values
            are C{'OPENSSH'}, C{'LSH'}, and C{'AGENTV3'}.
        @type type: L{str}

        @param extra: Any extra data supported by the selected format which
            is not part of the key itself.  For public OpenSSH keys, this is
            a comment.  For private OpenSSH keys, this is a passphrase to
            encrypt with.
        @type extra: L{bytes} or L{NoneType}

        @rtype: L{bytes}
        """
        method = getattr(self, '_toString_%s' % type.upper(), None)
        if method is None:
            raise BadKeyError('unknown type: %r' % (type[:30],))
        if method.__code__.co_argcount == 2:
            return method(extra)
        else:
            return method()

    @classmethod
    def generate(cls, key_type=DEFAULT_KEY_TYPE, key_size=DEFAULT_KEY_SIZE):
        """
        Return a new key.
        """
        if not key_type:
            key_type = 'not-specified'
        key_type = key_type.lower()

        if key_type == u'rsa':
            key_class = RSA
        elif key_type == u'dsa':
            key_class = DSA
        else:
            raise KeyCertException('Unknown key type "%s".' % (key_type))

        key = None
        try:
            key = key_class.generate(bits=key_size)
        except ValueError as error:
            raise KeyCertException(
                u'Wrong key size "%d". %s.' % (key_size, error))
        return cls(key)

    @classmethod
    def _guessStringType(cls, data):
        """
        Guess the type of key in data.

        The types map to _fromString_* methods.
        """
        if data.startswith(b'ssh-') or data.startswith(b'ecdsa-sha2-nistp'):
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
        elif data.startswith(b'\x00\x00\x00\x07ssh-'):
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
    def getKeyFormat(cls, data):
        """
        Return a type of key.
        """
        key_type = cls._guessStringType(data)
        human_readable = {
            'public_openssh': 'OpenSSH Public',
            'private_openssh': 'OpenSSH Private',
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

    @property
    def size(self):
        """
        Return the key size.
        """
        return self.keyObject.size() + 1

    def type(self):
        """
        Return the type of the object we wrap.  Currently this can only be
        'RSA' or 'DSA'.

        @rtype: L{str}
        """
        # the class is Crypto.PublicKey.<type>.<stuff we don't care about>
        mod = self.keyObject.__class__.__module__
        if mod.startswith('Crypto.PublicKey'):
            type = mod.split('.')[2]
        else:
            raise RuntimeError(
                'unknown type of object: %r' % (self.keyObject,))
        if type in ('RSA', 'DSA'):
            return type
        else:  # pragma: no cover
            raise RuntimeError('unknown type of key: %s' % (type,))

    def sshType(self):
        """Get the type of the object we wrap as defined in the SSH protocol,
        defined in RFC 4253, Section 6.6. Currently this can only be b'ssh-rsa'
        or b'ssh-dss'.

        @return: The key type format.
        @rtype: L{bytes}
        """
        return {'RSA': b'ssh-rsa', 'DSA': b'ssh-dss'}[self.type()]

    def data(self):
        """
        Return the values of the public key as a dictionary.

        @rtype: C{dict}
        """
        keyData = {}
        for name in self.keyObject.keydata:
            value = getattr(self.keyObject, name, None)
            if value is not None:
                keyData[name] = value
        return keyData

    def blob(self):
        """
        Return the public key blob for this key.  The blob is the
        over-the-wire format for public keys:

        RSA keys::
            string  'ssh-rsa'
            integer e
            integer n

        DSA keys::
            string  'ssh-dss'
            integer p
            integer q
            integer g
            integer y

        @rtype: C{bytes}
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
        else:  # pragma: no cover
            # Under normal usage we should not be able to reach this
            # branch. First self.type() will raise an error.
            raise BadKeyError("unknown key type %s" % (type,))

    def privateBlob(self):
        """
        Return the private key blob for this key.  The blob is the
        over-the-wire format for private keys:

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
        """
        type = self.type()
        data = self.data()
        if type == 'RSA':
            return (common.NS(b'ssh-rsa') + common.MP(data['n']) +
                    common.MP(data['e']) + common.MP(data['d']) +
                    common.MP(data['u']) + common.MP(data['p']) +
                    common.MP(data['q']))
        elif type == 'DSA':
            return (common.NS(b'ssh-dss') + common.MP(data['p']) +
                    common.MP(data['q']) + common.MP(data['g']) +
                    common.MP(data['y']) + common.MP(data['x']))

    def public(self):
        """
        Returns a version of this key containing only the public key data.
        If this is a public key, this may or may not be the same object
        as self.
        """
        return Key(self.keyObject.publickey())

    def isPublic(self):
        """
        Returns True if this Key is a public key.
        """
        return not self.keyObject.has_private()

    def fingerprint(self, format=FingerprintFormats.MD5_HEX):
        """
        The fingerprint of a public key consists of the output of the
        message-digest algorithm in the specified format.
        Supported formats include L{FingerprintFormats.MD5_HEX},
        L{FingerprintFormats.SHA256_BASE64} and
        L{FingerprintFormats.SHA1_BASE64}

        The input to the algorithm is the public key data as specified
        by [RFC4253].

        The output of sha256[RFC4634] and sha1[RFC3174] algorithms are
        presented to the user in the form of base64 encoded sha256 and sha1
        hashes, respectively.
        Examples:
            C{US5jTUa0kgX5ZxdqaGF0yGRu8EgKXHNmoT8jHKo1StM=}
            C{9CCuTybG5aORtuW4jrFcp0PbK4U=}

        The output of the MD5[RFC1321](default) algorithm is presented to the
        user as a sequence of 16 octets printed as hexadecimal with lowercase
        letters and separated by colons.
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
            return base64.b64encode(sha256(self.blob()).digest())
        elif format is FingerprintFormats.SHA1_BASE64:
            return base64.b64encode(sha1(self.blob()).digest())
        elif format is FingerprintFormats.MD5_HEX:
            return ':'.join([binascii.hexlify(x)
                             for x in iterbytes(md5(self.blob()).digest())])
        else:
            raise BadFingerPrintFormat(
                'Unsupported fingerprint format: %s' % (format,))

    def sign(self, data):
        """
        Returns a signature with this Key.

        @type data: C{bytes}
        @rtype: C{bytes}
        """
        if self.type() == 'RSA':
            digest = pkcs1Digest(data, self.keyObject.size() // 8)
            signature = self.keyObject.sign(digest, b'')[0]
            ret = common.NS(Util.number.long_to_bytes(signature))
        elif self.type() == 'DSA':
            digest = sha1(data).digest()
            randomBytes = self.secureRandom(19)
            sig = self.keyObject.sign(digest, randomBytes)
            # SSH insists that the DSS signature blob be two 160-bit integers
            # concatenated together. The sig[0], [1] numbers from obj.sign
            # are just numbers, and could be any length from 0 to 160 bits.
            # Make sure they are padded out to 160 bits (20 bytes each)
            ret = common.NS(Util.number.long_to_bytes(sig[0], 20) +
                            Util.number.long_to_bytes(sig[1], 20))
        else:  # pragma: no cover
            # We should not hit this branch under normal usage.
            raise BadKeyError('unknown key type %s' % (self.type(),))
        return common.NS(self.sshType()) + ret

    def verify(self, signature, data):
        """
        Returns true if the signature for data is valid for this Key.

        @type signature: C{bytes}
        @type data: C{bytes}
        @rtype: C{bool}
        """
        if len(signature) == 40:
            # DSA key with no padding
            signatureType, signature = b'ssh-dss', common.NS(signature)
        else:
            signatureType, signature = common.getNS(signature)
        if signatureType != self.sshType():
            return False
        if self.type() == 'RSA':
            numbers = common.getMP(signature)
            digest = pkcs1Digest(data, self.keyObject.size() // 8)
        elif self.type() == 'DSA':
            signature = common.getNS(signature)[0]
            numbers = [Util.number.bytes_to_long(n) for n in (signature[:20],
                       signature[20:])]
            digest = sha1(data).digest()
        else:  # pragma: no cover
            raise BadKeyError('unknown key type %s' % (self.type(),))
        return self.keyObject.verify(digest, numbers)

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

        @type blob: C{bytes}
        @return: a C{Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if the key type (the first string) is unknown.
        """
        keyType, rest = common.getNS(blob)

        if keyType == b'ssh-rsa':
            e, n, rest = common.getMP(rest, 2)
            return cls(RSA.construct((n, e)))
        elif keyType == b'ssh-dss':
            p, q, g, y, rest = common.getMP(rest, 4)
            return cls(DSA.construct((y, g, p, q)))
        else:
            raise BadKeyError('Unknown blob type: %r' % keyType[:30])

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

        @type blob: C{bytes}
        @return: a C{Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if the key type (the first string) is unknown.
        """
        keyType, rest = common.getNS(blob)

        if keyType == b'ssh-rsa':
            n, e, d, u, p, q, rest = common.getMP(rest, 6)
            rsakey = cls(RSA.construct((n, e, d, p, q, u)))
            return rsakey
        elif keyType == b'ssh-dss':
            p, q, g, y, x, rest = common.getMP(rest, 5)
            dsakey = cls(DSA.construct((y, g, p, q, x)))
            return dsakey
        else:
            raise BadKeyError('Unknown blob type: %r' % keyType[:30])

    @classmethod
    def _fromString_PUBLIC_OPENSSH(cls, data):
        """
        Return a public key object corresponding to this OpenSSH public key
        string.  The format of an OpenSSH public key string is::
            <key type> <base64-encoded public key blob>

        @type data: C{bytes}
        @return: A {Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if the blob type is unknown.
        """
        blob = base64.decodestring(data.split()[1])
        return cls._fromString_BLOB(blob)

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
        return cls(RSA.construct((n, e)))

    @classmethod
    def _fromString_PRIVATE_OPENSSH(cls, data, passphrase):
        """
        Return a private key object corresponding to this OpenSSH private key
        string.  If the key is encrypted, passphrase MUST be provided.
        Providing a passphrase for an unencrypted key is an error.

        The format of an OpenSSH private key string is::
            -----BEGIN <key type> PRIVATE KEY-----
            [Proc-Type: 4,ENCRYPTED
            DEK-Info: DES-EDE3-CBC,<initialization value>]
            <base64-encoded ASN.1 structure>
            ------END <key type> PRIVATE KEY------

        The ASN.1 structure of a RSA key is::
            (0, n, e, d, p, q)

        The ASN.1 structure of a DSA key is::
            (0, p, q, g, y, x)

        @type data: C{bytes}
        @type passphrase: C{bytes}
        @return: a C{Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if
            * a passphrase is provided for an unencrypted key
            * the ASN.1 encoding is incorrect
        @raises EncryptedKeyError: if
            * a passphrase is not provided for an encrypted key
        """
        lines = data.strip().splitlines()
        kind = lines[0].split(b' ')[1]
        if lines[1].startswith(b'Proc-Type: 4,ENCRYPTED'):  # encrypted key
            if not passphrase:
                raise EncryptedKeyError('Passphrase must be provided '
                                        'for an encrypted key')

            # Determine cipher and initialization vector
            try:
                _, cipher_iv_info = lines[2].split(b' ', 1)
                cipher, ivdata = cipher_iv_info.rstrip().split(b',', 1)
            except ValueError:
                raise BadKeyError('invalid DEK-info %r' % (lines[2][:30],))

            if cipher == b'AES-128-CBC':
                CipherClass = AES
                keySize = 16
                if len(ivdata) != 32:
                    raise BadKeyError('AES encrypted key with a bad IV')
            elif cipher == b'DES-EDE3-CBC':
                CipherClass = DES3
                keySize = 24
                if len(ivdata) != 16:
                    raise BadKeyError('DES encrypted key with a bad IV')
            else:
                raise BadKeyError('unknown encryption type %r' % cipher[:30])

            # extract keyData for decoding
            iv = bytes(bytearray([int(ivdata[i:i + 2], 16)
                                  for i in range(0, len(ivdata), 2)]))
            ba = md5(passphrase + iv[:8]).digest()
            bb = md5(ba + passphrase + iv[:8]).digest()
            decKey = (ba + bb)[:keySize]
            b64Data = base64.decodestring(b''.join(lines[3:-1]))
            keyData = CipherClass.new(decKey,
                                      CipherClass.MODE_CBC,
                                      iv).decrypt(b64Data)
            removeLen = ord(keyData[-1:])
            keyData = keyData[:-removeLen]
        else:
            if passphrase:
                raise BadKeyError('OpenSSH key not encrypted')
            b64Data = b''.join(lines[1:-1])
            keyData = base64.decodestring(b64Data)

        try:
            decodedKey = berDecoder.decode(keyData)[0]
        except PyAsn1Error as e:
            raise BadKeyError(
                'Failed to decode key (Bad Passphrase?): %s' % (e,))

        if kind == b'RSA':
            if len(decodedKey) == 2:  # alternate RSA key
                decodedKey = decodedKey[0]
            if len(decodedKey) < 6:
                raise BadKeyError('RSA key failed to decode properly')

            n, e, d, p, q = [long(value) for value in decodedKey[1:6]]
            if p > q:  # make p smaller than q
                p, q = q, p
            return cls(RSA.construct((n, e, d, p, q)))
        elif kind == b'DSA':
            p, q, g, y, x = [long(value) for value in decodedKey[1: 6]]
            if len(decodedKey) < 6:
                raise BadKeyError('DSA key failed to decode properly')
            return cls(DSA.construct((y, g, p, q, x)))
        else:
            raise BadKeyError('Key type %r not supported.' % (kind[:30],))

    def _toString_OPENSSH(self, extra):
        """
        Return a public or private OpenSSH string.  See
        _fromString_PUBLIC_OPENSSH and _fromString_PRIVATE_OPENSSH for the
        string formats.  If extra is present, it represents a comment for a
        public key, or a passphrase for a private key.

        @param extra: Comment for a public key or passphrase for a
            private key
        @type extra: C{bytes}

        @rtype: C{bytes}
        """
        data = self.data()
        if self.isPublic():
            b64Data = base64.encodestring(self.blob()).replace(b'\n', b'')
            if not extra:
                extra = b''
            return (self.sshType() + b' ' + b64Data + b' ' + extra).strip()
        else:
            lines = [b''.join((b'-----BEGIN ', self.type().encode('ascii'),
                               b' PRIVATE KEY-----'))]
            if self.type() == 'RSA':
                p, q = data['p'], data['q']
                objData = (0, data['n'], data['e'], data['d'], q, p,
                           data['d'] % (q - 1), data['d'] % (p - 1),
                           data['u'])
            else:
                objData = (0, data['p'], data['q'], data['g'], data['y'],
                           data['x'])
            asn1Sequence = univ.Sequence()
            for index, value in izip(itertools.count(), objData):
                asn1Sequence.setComponentByPosition(index, univ.Integer(value))
            asn1Data = berEncoder.encode(asn1Sequence)
            if extra:
                iv = self.secureRandom(8)
                hexiv = ''.join(['%02X' % ord(x) for x in iterbytes(iv)])
                hexiv = hexiv.encode('ascii')
                lines.append(b'Proc-Type: 4,ENCRYPTED')
                lines.append(b'DEK-Info: DES-EDE3-CBC,' + hexiv + b'\n')
                ba = md5(extra + iv).digest()
                bb = md5(ba + extra + iv).digest()
                encKey = (ba + bb)[:24]
                padLen = 8 - (len(asn1Data) % 8)
                asn1Data += (chr(padLen) * padLen).encode('ascii')
                asn1Data = DES3.new(encKey, DES3.MODE_CBC,
                                    iv).encrypt(asn1Data)
            b64Data = base64.encodestring(asn1Data).replace(b'\n', b'')
            lines += [b64Data[i:i + 64] for i in range(0, len(b64Data), 64)]
            lines.append(b''.join((b'-----END ', self.type().encode('ascii'),
                                   b' PRIVATE KEY-----')))
            return b'\n'.join(lines)

    @classmethod
    def _fromString_PRIVATE_OPENSSH_V1(cls, data, passphrase):
        """
        PEM wrap and base64 encoded for:

        Check OpenSSH source file openssh-portable/PROTOCOL.key.

        openssh-key-v10x00    # NULL-terminated "Auth Magic" string
        32-bit length, "none"   # ciphername length and string
        32-bit length, "none"   # kdfname length and string
        32-bit length, nil      # kdfoptions (0 length, no kdf)
        32-bit 0x01             # number of keys, hard-coded to 1 (no length)
        32-bit length, sshpub   # public key in ssh format
            32-bit length, keytype
            32-bit length, pub0
            32-bit length, pub1
        32-bit length for rnd+prv+comment+pad
            64-bit random check bytes  # a random 32-bit int, repeated
            32-bit length, keytype  # the private key (including public)
            32-bit length, pub0     # Public Key parts
            32-bit length, pub1
            32-bit length, prv0     # Private Key parts
            ...                     # (number varies by type)
            32-bit length, comment  # comment string
            padding bytes 0x010203  # pad to blocksize (see notes below)
        """
        lines = data.strip().split(b'\n')
        data = base64.decodestring(b''.join(lines[1:-1]))
        if not data.startswith(b'openssh-key-v1\x00'):
            raise BadKeyError('Invalid OpenSSH v1.')
        data = data[15:]
        cipher_name, data = common.getNS(data)

        if cipher_name != b'none':
            raise EncryptedKeyError(
                'Encrypted OpenSSH v1 private key is not supported.')

        kdf_name, data = common.getNS(data)
        kdf_options, data = common.getNS(data)

        number_of_keys = struct.unpack('>I', data[:4])[0]
        data = data[4:]
        if number_of_keys != 1:
            raise BadKeyError(
                'Only a single OpenSSH v1 private key is supported.')

        public_key, data = common.getNS(data)
        private_key, _ = common.getNS(data)

        # Ignore the random 32bit.
        key_type, data = common.getNS(private_key[8:])

        if key_type == b'ssh-rsa':
            # Public part.
            n, data = common.getMP(data)
            e, data = common.getMP(data)
            # Private parts.
            d, data = common.getMP(data)
            u, data = common.getMP(data)
            q, data = common.getMP(data)
            p, data = common.getMP(data)
            comment, _ = common.getNS(data)
            return cls(RSA.construct((n, e, d, p, q, u)))

        if key_type == 'ssh-dss':
            p, data = common.getMP(data)
            q, data = common.getMP(data)
            g, data = common.getMP(data)
            y, data = common.getMP(data)
            x, data = common.getMP(data)
            comment, _ = common.getNS(data)
            return cls(DSA.construct((y, g, p, q, x)))

        raise BadKeyError('Unsupported OpenSSH v1 key type.')

    @classmethod
    def _fromString_PUBLIC_LSH(cls, data):
        """
        Return a public key corresponding to this LSH public key string.
        The LSH public key string format is::
            <s-expression: ('public-key', (<key type>, (<name, <value>)+))>

        The names for a RSA (key type 'rsa-pkcs1-sha1') key are: n, e.
        The names for a DSA (key type 'dsa') key are: y, g, p, q.

        @type data: C{bytes}
        @return: a C{Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if the key type is unknown
        """
        sexp = sexpy.parse(base64.decodestring(data[1:-1]))
        assert sexp[0] == b'public-key'
        kd = {}
        for name, data in sexp[1][1:]:
            kd[name] = common.getMP(common.NS(data))[0]
        if sexp[1][0] == b'dsa':
            return cls(DSA.construct((kd[b'y'], kd[b'g'], kd[b'p'], kd[b'q'])))
        elif sexp[1][0] == b'rsa-pkcs1-sha1':
            return cls(RSA.construct((kd[b'n'], kd[b'e'])))
        else:
            raise BadKeyError('unknown lsh key type %r' % (sexp[1][0][:30],))

    @classmethod
    def _fromString_PRIVATE_LSH(cls, data):
        """
        Return a private key corresponding to this LSH private key string.
        The LSH private key string format is::
            <s-expression: ('private-key', (<key type>, (<name>, <value>)+))>

        The names for a RSA (key type 'rsa-pkcs1-sha1') key are: n, e, d, p, q.
        The names for a DSA (key type 'dsa') key are: y, g, p, q, x.

        @type data: C{bytes}
        @return: a {Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if the key type is unknown
        """
        sexp = sexpy.parse(data)
        assert sexp[0] == b'private-key'
        kd = {}
        for name, data in sexp[1][1:]:
            kd[name] = common.getMP(common.NS(data))[0]
        if sexp[1][0] == b'dsa':
            assert len(kd) == 5, len(kd)
            return cls(DSA.construct((
                kd[b'y'], kd[b'g'], kd[b'p'], kd[b'q'], kd[b'x'])))
        elif sexp[1][0] == b'rsa-pkcs1':
            assert len(kd) == 8, len(kd)
            if kd[b'p'] > kd[b'q']:  # make p smaller than q
                kd[b'p'], kd[b'q'] = kd[b'q'], kd[b'p']
            return cls(RSA.construct((
                kd[b'n'], kd[b'e'], kd[b'd'], kd[b'p'], kd[b'q'])))
        else:
            raise BadKeyError('unknown lsh key type %r' % (sexp[1][0][:30],))

    def _toString_LSH(self):
        """
        Return a public or private LSH key.  See _fromString_PUBLIC_LSH and
        _fromString_PRIVATE_LSH for the key formats.

        @rtype: C{bytes}
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
            else:  # pragma: no cover
                raise BadKeyError("unknown key type %s" % (type,))
            return (b'{' + base64.encodestring(keyData).replace(b'\n', b'') +
                    b'}')
        else:
            if type == 'RSA':
                p, q = data['p'], data['q']
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
                                     [b'c', common.MP(data['u'])[4:]]]]])
            elif type == 'DSA':
                return sexpy.pack([[b'private-key',
                                    [b'dsa',
                                     [b'p', common.MP(data['p'])[4:]],
                                     [b'q', common.MP(data['q'])[4:]],
                                     [b'g', common.MP(data['g'])[4:]],
                                     [b'y', common.MP(data['y'])[4:]],
                                     [b'x', common.MP(data['x'])[4:]]]]])
            else:  # pragma: no cover
                raise BadKeyError("unknown key type %s'" % (type,))

    @classmethod
    def _fromString_AGENTV3(cls, data):
        """
        Return a private key object corresponding to the Secure Shell Key
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

        @type data: C{bytes}
        @return: a C{Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if the key type (the first string) is unknown
        """
        keyType, data = common.getNS(data)
        if keyType == b'ssh-dss':
            p, data = common.getMP(data)
            q, data = common.getMP(data)
            g, data = common.getMP(data)
            y, data = common.getMP(data)
            x, data = common.getMP(data)
            return cls(DSA.construct((y, g, p, q, x)))
        elif keyType == b'ssh-rsa':
            e, data = common.getMP(data)
            d, data = common.getMP(data)
            n, data = common.getMP(data)
            u, data = common.getMP(data)
            p, data = common.getMP(data)
            q, data = common.getMP(data)
            return cls(RSA.construct((n, e, d, p, q, u)))
        else:  # pragma: no cover
            raise BadKeyError("unknown key type %r" % (keyType[:30],))

    def _toString_AGENTV3(self):
        """
        Return a private Secure Shell Agent v3 key.  See
        _fromString_AGENTV3 for the key format.

        @rtype: C{bytes}
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
                'Bad magic number for SSH.com key %r' % magic_number)
        struct.unpack('>I', blob[4:8])[0]  # Ignore value for total size.
        type_signature, rest = common.getNS(blob[8:])

        key_type = None
        if type_signature.startswith('if-modn{sign{rsa'):
            key_type = 'rsa'
        elif type_signature.startswith('dl-modp{sign{dsa'):
            key_type = 'dsa'
        else:
            raise BadKeyError('Unknown SSH.com key type %s' % type_signature)

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
            key_data = DES3.new(
                encryption_key, mode=DES3.MODE_CBC, IV=b'\x00' * 8).decrypt(
                encrypted_blob)
        else:
            raise BadKeyError(
                'Encryption method not supported: %r' % (
                    cipher_type[:30]))

        try:
            payload, _ = common.getNS(key_data)
            if key_type == 'rsa':
                e, d, n, u, p, q, rest = cls._unpackMPSSHCOM(payload, 6)
                return cls(RSA.construct((n, e, d, p, q, u)))

            if key_type == 'dsa':
                # First 32bit is an uint with value 0. We just ignore it.
                p, g, q, y, x, rest = cls._unpackMPSSHCOM(payload[4:], 5)
                return cls(DSA.construct((y, g, p, q, x)))
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
            mp.append(
                Util.number.bytes_to_long(data[c + 4:c + 4 + length]))
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

        wire_number = Util.number.long_to_bytes(number)

        wire_length = (len(wire_number) * 8) - 7
        return struct.pack('>L', wire_length) + wire_number

    def _toString_SSHCOM(self, extra):
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
            return self._toString_SSHCOM_public(extra)
        else:
            return self._toString_SSHCOM_private(extra)

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
            raise BadKeyError('Unsupported key type %s' % type)

        payload_blob = common.NS(payload_blob)

        if extra:
            # We got a password, so encrypt it.
            cipher_type = '3des-cbc'
            padding = b'\x00' * (8 - (len(payload_blob) % 8))
            payload_blob = payload_blob + padding
            encryption_key = self._getDES3EncryptionKey(extra)
            encrypted_blob = DES3.new(
                encryption_key, mode=DES3.MODE_CBC, IV=b'\x00' * 8).encrypt(
                payload_blob)
        else:
            cipher_type = 'none'
            encrypted_blob = payload_blob

        # We first create the content without magic number and
        # total size, then compute the total size, and update the
        # final content.
        blob = (
            '%(type_signature)s'
            '%(cipher_type)s'
            '%(encrypted_blob)s'
            ) % {
            'type_signature': common.NS(type_signature),
            'cipher_type': common.NS(cipher_type),
            'encrypted_blob': common.NS(encrypted_blob),
            }
        total_size = 8 + len(blob)
        blob = (
            '%(magic)s'
            '%(total_size)s'
            '%(blob)s'
            ) % {
            'magic': struct.pack('>I', SSHCOM_MAGIC_NUMBER),
            'total_size': struct.pack('>I', total_size),
            'blob': blob,
            }

        # In the end, encode in base 64 and wrap it.
        blob = base64.b64encode(blob)
        lines.extend(textwrap.wrap(blob, 70))

        lines.append('---- END SSH2 ENCRYPTED PRIVATE KEY ----')
        return '\n'.join(lines)

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
        if key_type not in [b'ssh-rsa', b'ssh-dss']:
            raise BadKeyError('Unsupported key type: %r' % key_type[:30])

        encryption_type = lines[1][11:].strip().lower()

        if encryption_type == b'none':
            if passphrase:
                raise BadKeyError('PuTTY key not encrypted')
        elif encryption_type != b'aes256-cbc':
            raise BadKeyError(
                'Unsupported encryption type: %r' % encryption_type[:30])

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
                    key_type[:30], public_type[:30]))

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
            private_blob = AES.new(
                encryption_key, mode=AES.MODE_CBC, IV=b'\x00' * 16).decrypt(
                private_blob)

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
                        private_mac, computed_mac))

        if key_type == b'ssh-rsa':
            e, n, _ = common.getMP(public_payload, count=2)
            d, q, p, u, _ = common.getMP(private_blob, count=4)
            return cls(RSA.construct((n, e, d, p, q, u)))

        if key_type == b'ssh-dss':
            p, q, g, y, _ = common.getMP(public_payload, count=4)
            x, _ = common.getMP(private_blob)
            return cls(DSA.construct((y, g, p, q, x)))

    @staticmethod
    def _getPuttyAES256EncryptionKey(passphrase):
        """
        Return the encryption key used in Putty AES 256 cipher.
        """
        key_size = 32
        part_1 = sha1(b'\x00\x00\x00\x00' + passphrase).digest()
        part_2 = sha1(b'\x00\x00\x00\x01' + passphrase).digest()
        return (part_1 + part_2)[:key_size]

    def _toString_PUTTY(self, extra):
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
            return self._toString_SSHCOM_public(extra)
        else:
            return self._toString_PUTTY_private(extra)

    def _toString_PUTTY_private(self, extra):
        """
        Return the Putty private key representation.
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
            private_blob_encrypted = AES.new(
                encryption_key, mode=AES.MODE_CBC, IV=b'\x00' * aes_block_size,
                ).encrypt(private_blob_plain)

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
            raise BadKeyError('Failed to load certificate. %s' % (error,))

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
                'Failed to load PKCS#1 public key. %s' % (error,))

        return cls._fromOpenSSLPublic(pkey, 'X509 public PEM file')

    @classmethod
    def _fromOpenSSLPublic(cls, pkey, source_type):
        """
        Load the SSH from an OpenSSL Public Key object.
        """
        type_id = pkey.type()

        if type_id not in [6, 116]:
            raise BadKeyError(
                'Unsupported key found in the %s.' % (source_type,))

        ckey = pkey.to_cryptography_key()
        components = ckey.public_numbers()

        if type_id == 6:
            # RSA key.
            return cls(RSA.construct((long(components.n), long(components.e))))

        if type_id == 116:
            # DSA key.
            parameters = components.parameter_numbers
            return cls(DSA.construct((
                long(components.y),
                long(parameters.g),
                long(parameters.p),
                long(parameters.q)
                )))

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
            raise BadKeyError('Failed to load PKCS#8 PEM. %s' % (error,))

        type_id = key.type()

        if type_id not in [6, 116]:
            raise BadKeyError(
                'Unsupported key found in the PKCS#8 private PEM file.')

        ckey = key.to_cryptography_key()

        if type_id == 6:
            # RSA key.
            private = ckey.private_numbers()
            public = ckey.public_key().public_numbers()
            return cls(RSA.construct((
                long(public.n),
                long(public.e),
                long(private.d),
                long(private.q),
                long(private.p),
                long(private.iqmp),
                )))

        if type_id == 116:
            # DSA key.
            private = ckey.private_numbers()
            public = ckey.public_key().public_numbers()
            return cls(DSA.construct((
                long(public.y),
                long(public.parameter_numbers.g),
                long(public.parameter_numbers.p),
                long(public.parameter_numbers.q),
                long(private.x),
                )))


def objectType(obj):
    """
    Return the SSH key type corresponding to a
    C{Crypto.PublicKey.pubkey.pubkey} object.

    @type obj:  C{Crypto.PublicKey.pubkey.pubkey}
    @rtype:     C{str}
    """
    keyDataMapping = {
        ('n', 'e', 'd', 'p', 'q'): 'ssh-rsa',
        ('n', 'e', 'd', 'p', 'q', 'u'): 'ssh-rsa',
        ('y', 'g', 'p', 'q', 'x'): 'ssh-dss'
        }
    try:
        return keyDataMapping[tuple(obj.keydata)]
    except (KeyError, AttributeError):
        raise BadKeyError("invalid key object")


def pkcs1Pad(data, messageLength):
    """
    Pad out data to messageLength according to the PKCS#1 standard.
    @type data: C{bytes}
    @type messageLength: C{int}
    """
    lenPad = messageLength - 2 - len(data)
    return b'\x01' + (b'\xff' * lenPad) + b'\x00' + data


def pkcs1Digest(data, messageLength):
    """
    Create a message digest using the SHA1 hash algorithm according to the
    PKCS#1 standard.
    @type data: C{bytes}
    @type messageLength: C{int}
    """
    digest = sha1(data).digest()
    return pkcs1Pad(ID_SHA1 + digest, messageLength)


def lenSig(obj):
    """
    Return the length of the signature in bytes for a key object.

    @type obj: C{Crypto.PublicKey.pubkey.pubkey}
    @rtype: C{long}
    """
    return obj.size() // 8
