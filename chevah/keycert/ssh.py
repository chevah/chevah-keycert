# Copyright (c) 2014 Adi Roiban.
# See LICENSE for details.
"""
SSH keys management.
"""
import base64
import binascii
import hmac
import struct
import textwrap
from hashlib import md5, sha1
from socket import gethostname

from Crypto import Util
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import DSA, RSA
from OpenSSL import crypto, rand
from twisted.conch.ssh import common
from twisted.conch.ssh.keys import (
    BadKeyError,
    EncryptedKeyError,
    Key as ConchSSHKey,
    )

from chevah.compat import local_filesystem

KEY_CLASSES = {
    crypto.TYPE_RSA: RSA,
    crypto.TYPE_DSA: DSA,
    }

DEFAULT_PUBLIC_KEY_EXTENSION = u'.pub'
DEFAULT_KEY_SIZE = 1024
DEFAULT_KEY_TYPE = crypto.TYPE_RSA
SSHCOM_MAGIC_NUMBER = int('3f6ff9eb', base=16)
PUTTY_HMAC_KEY = 'putty-private-key-file-mac-key'


class KeyCertException(Exception):
    """
    General exception raised by this module.
    """


def generate_ssh_key(options, key=None, open_method=None):
    """
    Generate a SSH RSA or DSA key and store it on disk.

    Return a pair of (exit_code, operation_message).

    For success, exit_code is 0.

    `key` and `open_method` are helpers for dependency injection
    during tests.
    """
    if key is None:
        key = Key()

    if open_method is None:
        open_method = open

    exit_code = 0
    message = ''
    try:
        key_size = options.key_size

        if options.key_type.lower() == u'rsa':
            key_type = crypto.TYPE_RSA
        elif options.key_type.lower() == u'dsa':
            key_type = crypto.TYPE_DSA
        else:
            key_type = options.key_type

        if not hasattr(options, 'key_file') or options.key_file is None:
            options.key_file = 'id_%s' % (options.key_type.lower())

        private_file = options.key_file

        public_file = u'%s%s' % (
            options.key_file, DEFAULT_PUBLIC_KEY_EXTENSION)

        skip = _skip_key_generation(options, private_file, public_file)
        if skip:
            return (0, u'Key already exists.')

        key.generate(key_type=key_type, key_size=key_size)

        private_file_path = local_filesystem.getEncodedPath(private_file)
        public_file_path = local_filesystem.getEncodedPath(public_file)

        with open_method(private_file_path, 'wb') as file_handler:
            key.store(private_file=file_handler)

        key_comment = None
        if hasattr(options, 'key_comment') and options.key_comment:
            key_comment = options.key_comment
            message_comment = u'having comment "%s"' % key_comment
        else:
            message_comment = u'without a comment'

        with open_method(public_file_path, 'wb') as file_handler:
            key.store(public_file=file_handler, comment=key_comment)

        message = (
            u'SSH key of type "%s" and length "%d" generated as '
            u'public key file "%s" and private key file "%s" %s.') % (
            options.key_type,
            key_size,
            public_file,
            private_file,
            message_comment,
            )

        exit_code = 0

    except KeyCertException, error:
        exit_code = 1
        message = error.message

    return (exit_code, message)


def _skip_key_generation(options, private_file, public_file):
    """
    Return True when key generation can be skipped.

    Key generation can be skipped when private key already exists. Public
    key is ignored.

    Raise KeyCertException if file exists.
    """
    private_segments = local_filesystem.getSegmentsFromRealPath(private_file)
    if local_filesystem.exists(private_segments):
        if options.migrate:
            return True
        else:
            raise KeyCertException(
                u'Private key already exists. %s' % private_file)

    public_segments = local_filesystem.getSegmentsFromRealPath(public_file)
    if local_filesystem.exists(public_segments):
        raise KeyCertException(u'Public key already exists. %s' % public_file)


class Key(ConchSSHKey):
    """
    Key used by SSH implementations.

    On top of Twisted key it adds:
    * Generate a key.
    * support for handling ssh.com key RFC 4716 and RFC 5208 (for private)
    """

    def __init__(self, keyObject=None):
        super(Key, self).__init__(keyObject)

    def generate(self, key_type=DEFAULT_KEY_TYPE, key_size=DEFAULT_KEY_SIZE):
        '''Create the key data.'''
        if key_type not in [crypto.TYPE_RSA, crypto.TYPE_DSA]:
            raise KeyCertException('Unknown key type "%s".' % (key_type))

        key = None
        key_class = KEY_CLASSES[key_type]
        try:
            key = key_class.generate(bits=key_size, randfunc=rand.bytes)
        except ValueError, error:
            raise KeyCertException(
                u'Wrong key size "%d". %s.' % (key_size, error))
        self.keyObject = key

    @property
    def size(self):
        '''Return the key size.'''
        return self.keyObject.size() + 1

    @property
    def private_openssh(self):
        '''Return the OpenSSH representation for the public key part.'''
        return self.toString(type='openssh')

    @property
    def public_openssh(self):
        '''Return the OpenSSH representation for private key part.'''
        return self.public().toString(type='openssh')

    def store(
            self, public_file=None, private_file=None, comment=None):
        '''Store the public and private key into a file.'''
        if public_file:
            if comment:
                public_content = '%s %s' % (
                    self.public_openssh, comment.encode('utf-8'))
            else:
                public_content = self.public_openssh
            public_file.write(public_content)
        if private_file:
            private_file.write(self.private_openssh)

    def public(self):
        """
        Returns a version of this key containing only the public key data.
        If this is a public key, this may or may not be the same object
        as self.
        """
        return Key(self.keyObject.publickey())

    @classmethod
    def fromString(cls, data, type=None, passphrase=None):
        """
        Return a Key object corresponding to the string data.
        type is optionally the type of string, matching a _fromString_*
        method.  Otherwise, the _guessStringType() classmethod will be used
        to guess a type.  If the key is encrypted, passphrase is used as
        the decryption key.

        @type data: C{str}
        @type type: C{None}/C{str}
        @type passphrase: C{None}/C{str}
        @rtype: C{Key}
        """
        if type is None:
            type = cls._guessStringType(data)
        if type is None:
            raise BadKeyError('Cannot guess the type for %r' % data[:80])
        try:
            return super(cls, Key).fromString(
                data, type=type, passphrase=passphrase)
        except (IndexError):
            raise BadKeyError('Key is too short.')
        except (struct.error,  binascii.Error, TypeError):
            raise BadKeyError('Fail to parse key content.')

    @classmethod
    def _guessStringType(cls, data):
        """
        Guess the type of key in data.

        The types map to _fromString_* methods.
        """
        if data.startswith('ssh-'):
            return 'public_openssh'
        elif data.startswith('---- BEGIN SSH2 PUBLIC KEY ----'):
            return 'public_sshcom'
        elif data.startswith('---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----'):
            return 'private_sshcom'
        elif data.startswith('-----BEGIN'):
            return 'private_openssh'
        elif data.startswith('PuTTY-User-Key-File-2'):
            return 'private_putty'
        elif data.startswith('{'):
            return 'public_lsh'
        elif data.startswith('('):
            return 'private_lsh'
        elif data.startswith('\x00\x00\x00\x07ssh-'):
            ignored, rest = common.getNS(data)
            count = 0
            while rest:
                count += 1
                ignored, rest = common.getMP(rest)
            if count > 4:
                return 'agentv3'
            else:
                return 'blob'

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
        @raises BadKeyError: if the blob type is unknown.
        """
        blob = cls._getSSHCOMKeyContent(data)
        magic_number = struct.unpack('>I', blob[:4])[0]
        if magic_number != SSHCOM_MAGIC_NUMBER:
            raise BadKeyError(
                'Bad magic number for SSH.com key %s' % magic_number)
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

        if cipher_type.lower() not in ['none', '3des-cbc']:
            raise BadKeyError(
                'Encryption method not supported: %s' % (
                    cipher_type))

        encryption_key = None
        if cipher_type.lower() == '3des-cbc':
            if not passphrase:
                raise EncryptedKeyError(
                    'Passphrase must be provided for an encrypted key.')
            encryption_key = cls._getDES3EncryptionKey(passphrase)
            key_data = DES3.new(
                encryption_key, mode=DES3.MODE_CBC, IV='\x00' * 8).decrypt(
                encrypted_blob)
        else:
            # No encryption.
            key_data = encrypted_blob

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
            length = (length + 7) / 8
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
        else:
            raise BadKeyError('Unsupported key type %s' % type)

        payload_blob = common.NS(payload_blob)

        if extra:
            # We got a password, so encrypt it.
            cipher_type = '3des-cbc'
            padding = '\x00' * (8 - (len(payload_blob) % 8))
            payload_blob = payload_blob + padding
            encryption_key = self._getDES3EncryptionKey(extra)
            encrypted_blob = DES3.new(
                encryption_key, mode=DES3.MODE_CBC, IV='\x00' * 8).encrypt(
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
        if key_type not in ['ssh-rsa', 'ssh-dss']:
            raise BadKeyError('Unsupported key type: %s' % key_type)

        encryption_type = lines[1][11:].strip().lower()

        if encryption_type not in ['none', 'aes256-cbc']:
            raise BadKeyError(
                'Unsupported encryption type: %s' % encryption_type)

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
                'Mismatch key type. Header has %s, public has %s' % (
                    key_type, public_type))

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
        if encryption_type == 'aes256-cbc':
            if not passphrase:
                raise EncryptedKeyError(
                    'Passphrase must be provided for an encrypted key.')
            hmac_key += passphrase
            encryption_key = cls._getPuttyAES256EncryptionKey(passphrase)
            private_blob = AES.new(
                encryption_key, mode=AES.MODE_CBC, IV='\x00' * 16).decrypt(
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

        if key_type == 'ssh-rsa':
            e, n, _ = common.getMP(public_payload, count=2)
            d, q, p, u, _ = common.getMP(private_blob, count=4)
            return cls(RSA.construct((n, e, d, p, q, u)))

        if key_type == 'ssh-dss':
            p, q, g, y, _ = common.getMP(public_payload, count=4)
            x, _ = common.getMP(private_blob)
            return cls(DSA.construct((y, g, p, q, x)))

    @staticmethod
    def _getPuttyAES256EncryptionKey(passphrase):
        """
        Return the encryption key used in Putty AES 256 cipher.
        """
        key_size = 32
        part_1 = sha1('\x00\x00\x00\x00' + passphrase).digest()
        part_2 = sha1('\x00\x00\x00\x01' + passphrase).digest()
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
        comment = 'Exported by Twisted.'
        data = self.data()

        hmac_key = PUTTY_HMAC_KEY
        if extra:
            encryption_type = 'aes256-cbc'
            hmac_key += extra
        else:
            encryption_type = 'none'

        if key_type == 'ssh-rsa':
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
        elif key_type == 'ssh-dss':
            public_blob = (
                common.NS(key_type) +
                common.MP(data['p']) +
                common.MP(data['q']) +
                common.MP(data['g']) +
                common.MP(data['y'])
                )
            private_blob = common.MP(data['x'])
        else:
            raise BadKeyError('Unsupported key type.')

        private_blob_plain = private_blob
        private_blob_encrypted = private_blob

        if extra:
            # Encryption is requested.
            # Padding is required for encryption.
            padding_size = -1 * (
                (len(private_blob) % aes_block_size) - aes_block_size)
            private_blob_plain += '\x00' * padding_size
            encryption_key = self._getPuttyAES256EncryptionKey(extra)
            private_blob_encrypted = AES.new(
                encryption_key, mode=AES.MODE_CBC, IV='\x00' * aes_block_size,
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
