# Copyright (c) 2014 Adi Roiban.
# See LICENSE for details.
"""
Test for SSH keys management.
"""
from OpenSSL import crypto
from StringIO import StringIO
import textwrap

from chevah.empirical import mk, EmpiricalTestCase
from mock import call, Mock
from nose.plugins.attrib import attr

from chevah.keycert.ssh import (
    BadKeyError,
    KeyCertException,
    EncryptedKeyError,
    Key,
    generate_ssh_key,
    )

PUBLIC_RSA_ARMOR_START = u'-----BEGIN PUBLIC KEY-----\n'
PUBLIC_RSA_ARMOR_END = u'\n-----END PUBLIC KEY-----\n'
PRIVATE_RSA_ARMOR_START = u'-----BEGIN RSA PRIVATE KEY-----\n'
PRIVATE_RSA_ARMOR_END = u'\n-----END RSA PRIVATE KEY-----\n'
PUBLIC_DSA_ARMOR_START = u'-----BEGIN PUBLIC KEY-----\n'
PUBLIC_DSA_ARMOR_END = u'\n-----END PUBLIC KEY-----\n'
PRIVATE_DSA_ARMOR_START = u'-----BEGIN DSA PRIVATE KEY-----\n'
PRIVATE_DSA_ARMOR_END = u'\n-----END DSA PRIVATE KEY-----\n'

OPENSSH_RSA_PRIVATE = ('''-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----''')

OPENSSH_RSA_PUBLIC = (
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTKA'
    'PkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk+X6Lc4+lAf'
    'p1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcjRToF6/jpLw=='
    )

OPENSSH_DSA_PRIVATE = ('''-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQDOwkKGnmVZ9bRl7ZCn/wSELV0n5ELsqVZFOtBpHleEOitsvjEB
BbTKX0fZ83vaMVnJFVw3DQSbi192krvk909Y6h3HVO2MKBRd9t29fr26VvCZQOxR
4fzkPuL+Px4+ShqE171sOzsuEDt0Mkxf152QxrA2vPowkj7fmzRH5xgDTQIVAIYb
/ljSUclo6TiNwoiF+9byafFJAoGAXA+TAGCmF2ZeNZN04mgxeyT34IAw37NGmLLP
/byi86dKcdz5htqPiOWcNmFzrA7a0o+erE3B+miwEm2sVz+eVWfNOCJQalHUqRrk
1iV542FL0BCePiJa91Baw4pVS5hnSNko/Wsp0VnW3q5OK/tPs1pRy+3qWUwwrg5i
zhYkBfwCgYB/6sL9MO4ZwtFzwbOKNOoZxfORwNbzzHf+IpzyBTxxQJcYS6QgbtSi
2tUY1WeJxmq/xkMoVLgpmpK6NN+NuB6aux54U7h5B3pZ7SnoRJ7vATQnMJpwZYno
8uZXhx4TmOoSxzxy2jTJb4rt4R6bbwjaI9ca/1iLavocQ218Zk204gIUTk7aRv65
oTedYsAyi80L8phYBN4=
-----END DSA PRIVATE KEY-----''')

OPENSSH_DSA_PUBLIC = (
    'ssh-dss AAAAB3NzaC1kc3MAAACBAM7CQoaeZVn1tGXtkKf/BIQtXSfkQuypVkU60GkeV4Q6K'
    '2y+MQEFtMpfR9nze9oxWckVXDcNBJuLX3aSu+T3T1jqHcdU7YwoFF323b1+vbpW8JlA7FHh/O'
    'Q+4v4/Hj5KGoTXvWw7Oy4QO3QyTF/XnZDGsDa8+jCSPt+bNEfnGANNAAAAFQCGG/5Y0lHJaOk'
    '4jcKIhfvW8mnxSQAAAIBcD5MAYKYXZl41k3TiaDF7JPfggDDfs0aYss/9vKLzp0px3PmG2o+I'
    '5Zw2YXOsDtrSj56sTcH6aLASbaxXP55VZ804IlBqUdSpGuTWJXnjYUvQEJ4+Ilr3UFrDilVLm'
    'GdI2Sj9aynRWdberk4r+0+zWlHL7epZTDCuDmLOFiQF/AAAAIB/6sL9MO4ZwtFzwbOKNOoZxf'
    'ORwNbzzHf+IpzyBTxxQJcYS6QgbtSi2tUY1WeJxmq/xkMoVLgpmpK6NN+NuB6aux54U7h5B3p'
    'Z7SnoRJ7vATQnMJpwZYno8uZXhx4TmOoSxzxy2jTJb4rt4R6bbwjaI9ca/1iLavocQ218Zk20'
    '4g=='
    )

# Same key as OPENSSH_RSA_PUBLIC, wrapped at 70 characters.
SSHCOM_RSA_PUBLIC = """---- BEGIN SSH2 PUBLIC KEY ----
AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTKAPkPAW
zlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk+X6Lc4+lAfp1
YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcjRToF6/jpLw==
---- END SSH2 PUBLIC KEY ----"""

# Same key as OPENSSH_DSA_PUBLIC.
SSHCOM_DSA_PUBLIC = """---- BEGIN SSH2 PUBLIC KEY ----
AAAAB3NzaC1kc3MAAACBAM7CQoaeZVn1tGXtkKf/BIQtXSfkQuypVkU60GkeV4Q6K2y+MQ
EFtMpfR9nze9oxWckVXDcNBJuLX3aSu+T3T1jqHcdU7YwoFF323b1+vbpW8JlA7FHh/OQ+
4v4/Hj5KGoTXvWw7Oy4QO3QyTF/XnZDGsDa8+jCSPt+bNEfnGANNAAAAFQCGG/5Y0lHJaO
k4jcKIhfvW8mnxSQAAAIBcD5MAYKYXZl41k3TiaDF7JPfggDDfs0aYss/9vKLzp0px3PmG
2o+I5Zw2YXOsDtrSj56sTcH6aLASbaxXP55VZ804IlBqUdSpGuTWJXnjYUvQEJ4+Ilr3UF
rDilVLmGdI2Sj9aynRWdberk4r+0+zWlHL7epZTDCuDmLOFiQF/AAAAIB/6sL9MO4ZwtFz
wbOKNOoZxfORwNbzzHf+IpzyBTxxQJcYS6QgbtSi2tUY1WeJxmq/xkMoVLgpmpK6NN+NuB
6aux54U7h5B3pZ7SnoRJ7vATQnMJpwZYno8uZXhx4TmOoSxzxy2jTJb4rt4R6bbwjaI9ca
/1iLavocQ218Zk204g==
---- END SSH2 PUBLIC KEY ----"""

# Same as OPENSSH_RSA_PRIVATE
SSHCOM_RSA_PRIVATE_NO_PASSWORD = """---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
P2/56wAAAi4AAAA3aWYtbW9kbntzaWdue3JzYS1wa2NzMS1zaGExfSxlbmNyeXB0e3JzYS
1wa2NzMXYyLW9hZXB9fQAAAARub25lAAAB3wAAAdsAAAARAQABAAAD+QgeXEA78ZgXYGFa
bsuNw3bmm05ke9RxWjRZfpxOb8BcVKl9KhTkKRtBNgr+es3rD809SVgYqn30oq+Ikox/5Z
7JGZzPSdcX6Z6CeR083Bh2gWFRRBF0unzrMlk9eaGOym+q0QU51ldCJ7P9OR4ad/K/0Ufz
uKaAftzcECQ5f+oBAAAD+bh9Xq1JqQNIHpmi/KAux/WIL0/e0kd49MoA+Q8BbOW7kFEdyY
C7S5OOfsaGunFuONYzANU3Q7HPDu14jQ4QhWSmeVzIzovmYaT5fotzj6UB+nVjEJH2j34V
cxZIk/faNHAj7guFZjGdhSV28A7ksPP1B5HTIqKbByNFOgXr+OkvAAAB+X+ARfXlS8UUPQ
ODJvSJLeJRfIoup2uJ8XbRMz/Kdiz/bS6h2FKGzWp8QfuzLIuH94GMrinThp1h6g9lOB3C
3TEAAAH5y5EDU2F42Xm6tvQzM8bAgq7d2/x2iHRuOkDUb1bK3YwByTihl9BLqvdRhRxpl2
1EcqWpB/RzAFbGa+60G/iV7wAAAfnoAnRdC+5SyjrZ1JQUWUkapiYHIhFq6kWtGm3kWJn0
IxCBtFhGvqIWJwZIAjf6tTKMUk6bjG9p7JpetXUsTiDB
---- END SSH2 ENCRYPTED PRIVATE KEY ----"""

# Same as OPENSSH_RSA_PRIVATE and with 'chevah' password.
SSHCOM_RSA_PRIVATE_WITH_PASSWORD = (
    """---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
P2/56wAAAjMAAAA3aWYtbW9kbntzaWdue3JzYS1wa2NzMS1zaGExfSxlbmNyeXB0e3JzYS
1wa2NzMXYyLW9hZXB9fQAAAAgzZGVzLWNiYwAAAeAqUfFcnQIi4HEOAvAoJp8nIsw3WZMc
MhWiSWenwY0tKZPxngo1s2p8QkIclw0Tu7twvtG2zABb4x/jfyqLPc5brvBdYiAXMg1xPS
xzJ7gmaYLbAJEeQxdzPqXmxJXvxSwElYhozCFHpTYm56PYBONUSbV2ORCA4eEn9VjFRxqX
Q/XQ433aF4ZlnCVl+tCJRxhfjDTw/p5jfVETVwqdm7XCM2rGYvHxqn5uUxOl+jUorDtPHu
aPZGuKND1rGWSve8p9RA662P/M6HNHMq5w5mEKKc6aOikSFWwFe3vKZ3nE1WtXEvE2bgBD
1rvYLBp9tFx4U3uQAMxvVQAeyYNeK9Qt11IMg7+seskBmVQNXo2h3Wbn8TRUxSscgQNfnm
BnNIQQbiaMEk1Em8K2I5L+DRrcOzSvkVBNguOaiLCuSbP4f4JkAvD743scRFrT3QgCdjqr
4FHJG/z/D7dEbeC3mJfXFrM7PgCGFx9L6/FqLC+piJmyEq8nggkg9P0o+oJ7/c/xGU7at9
BsDKrM0FEXc8bFp39e8BNRbikCD61zfFp7B1s64y1mmqJkDYe2pH7FUA9mbC3vv6YM9tsY
fWGAGt8dHGIMM6MrzZYr8xJLwdmPDwAtFt2GR1Y8M0vnw6WtoL4=
---- END SSH2 ENCRYPTED PRIVATE KEY ----""")

SSHCOM_DSA_PRIVATE_NO_PASSWORD = """---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
P2/56wAAAgIAAAAmZGwtbW9kcHtzaWdue2RzYS1uaXN0LXNoYTF9LGRoe3BsYWlufX0AAA
AEbm9uZQAAAcQAAAHAAAAAAAAAA/nOwkKGnmVZ9bRl7ZCn/wSELV0n5ELsqVZFOtBpHleE
OitsvjEBBbTKX0fZ83vaMVnJFVw3DQSbi192krvk909Y6h3HVO2MKBRd9t29fr26VvCZQO
xR4fzkPuL+Px4+ShqE171sOzsuEDt0Mkxf152QxrA2vPowkj7fmzRH5xgDTQAAA/lcD5MA
YKYXZl41k3TiaDF7JPfggDDfs0aYss/9vKLzp0px3PmG2o+I5Zw2YXOsDtrSj56sTcH6aL
ASbaxXP55VZ804IlBqUdSpGuTWJXnjYUvQEJ4+Ilr3UFrDilVLmGdI2Sj9aynRWdberk4r
+0+zWlHL7epZTDCuDmLOFiQF/AAAAJmGG/5Y0lHJaOk4jcKIhfvW8mnxSQAAA/l/6sL9MO
4ZwtFzwbOKNOoZxfORwNbzzHf+IpzyBTxxQJcYS6QgbtSi2tUY1WeJxmq/xkMoVLgpmpK6
NN+NuB6aux54U7h5B3pZ7SnoRJ7vATQnMJpwZYno8uZXhx4TmOoSxzxy2jTJb4rt4R6bbw
jaI9ca/1iLavocQ218Zk204gAAAJlOTtpG/rmhN51iwDKLzQvymFgE3g==
---- END SSH2 ENCRYPTED PRIVATE KEY ----"""

# Same as OPENSSH_RSA_PRIVATE
# Make sure it has Windows newlines.
PUTTY_RSA_PRIVATE_NO_PASSWORD = """PuTTY-User-Key-File-2: ssh-rsa\r
Encryption: none\r
Comment: imported-openssh-key\r
Public-Lines: 4\r
AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTK\r
APkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk\r
+X6Lc4+lAfp1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcj\r
RToF6/jpLw==\r
Private-Lines: 8\r
AAAAgAgeXEA78ZgXYGFabsuNw3bmm05ke9RxWjRZfpxOb8BcVKl9KhTkKRtBNgr+\r
es3rD809SVgYqn30oq+Ikox/5Z7JGZzPSdcX6Z6CeR083Bh2gWFRRBF0unzrMlk9\r
eaGOym+q0QU51ldCJ7P9OR4ad/K/0UfzuKaAftzcECQ5f+oBAAAAQQDoAnRdC+5S\r
yjrZ1JQUWUkapiYHIhFq6kWtGm3kWJn0IxCBtFhGvqIWJwZIAjf6tTKMUk6bjG9p\r
7JpetXUsTiDBAAAAQQDLkQNTYXjZebq29DMzxsCCrt3b/HaIdG46QNRvVsrdjAHJ\r
OKGX0Euq91GFHGmXbURypakH9HMAVsZr7rQb+JXvAAAAQH+ARfXlS8UUPQODJvSJ\r
LeJRfIoup2uJ8XbRMz/Kdiz/bS6h2FKGzWp8QfuzLIuH94GMrinThp1h6g9lOB3C\r
3TE=\r
Private-MAC: 7630b86be300c6302ce1390fb264487bb61e67ce"""

# Same as OPENSSH_RSA_PRIVATE, with 'chevah' password.
PUTTY_RSA_PRIVATE_WITH_PASSWORD = """PuTTY-User-Key-File-2: ssh-rsa\r
Encryption: aes256-cbc\r
Comment: imported-openssh-key\r
Public-Lines: 4\r
AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTK\r
APkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk\r
+X6Lc4+lAfp1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcj\r
RToF6/jpLw==\r
Private-Lines: 8\r
dqtZBETu8cK9VpOX/IB9iIehQE7r6ceVvzsDqrjwGnw64LkEoqlqobP7diV3/gpc\r
b1Vmf8EitczdQBUdWkVtSJVA7FYBUNQlBd4ghkDJm58goTVzdGxpoafpQ9nFNO72\r
iQFg1wfpJQn9fcR0vQL1s5uykCSeEy232rHeFO4tMssq4xrhLqK9vWaYilWJoBxM\r
jzmVdL04QJERTJXh7k3wsRWGO12r+PGnp/8upiHHfnjVZlzDw6Dw6WQ+EaqI99mm\r
Cgo4ZiBwubHtPZq+eeP8Db/m3lMaKQNKAyYe3VlKCUwkC8N4jZR8QQlaOjBfHfPR\r
vO+Znb71OYvwFHQbwA3K64M9KnWCdXZxdCrBvm2UuEcKBz7SDEXQV2UvtGueg0s0\r
EO5R1D0fXky8HGA6VciUGR6g2zclO6rNR+Ooc5ThsZQ9sKVrpcvYYC8WdZ5LB50B\r
J8IuFywygVI4PbRs98v9Dg==\r
Private-MAC: 3ffe2587759ff8f50c6acdcad44f62a67e88ef2b"""

# This is the same key as OPENSSH_DSA_PRIVATE
PUTTY_DSA_PRIVATE_NO_PASSWORD = """PuTTY-User-Key-File-2: ssh-dss\r
Encryption: none\r
Comment: imported-openssh-key\r
Public-Lines: 10\r
AAAAB3NzaC1kc3MAAACBAM7CQoaeZVn1tGXtkKf/BIQtXSfkQuypVkU60GkeV4Q6\r
K2y+MQEFtMpfR9nze9oxWckVXDcNBJuLX3aSu+T3T1jqHcdU7YwoFF323b1+vbpW\r
8JlA7FHh/OQ+4v4/Hj5KGoTXvWw7Oy4QO3QyTF/XnZDGsDa8+jCSPt+bNEfnGANN\r
AAAAFQCGG/5Y0lHJaOk4jcKIhfvW8mnxSQAAAIBcD5MAYKYXZl41k3TiaDF7JPfg\r
gDDfs0aYss/9vKLzp0px3PmG2o+I5Zw2YXOsDtrSj56sTcH6aLASbaxXP55VZ804\r
IlBqUdSpGuTWJXnjYUvQEJ4+Ilr3UFrDilVLmGdI2Sj9aynRWdberk4r+0+zWlHL\r
7epZTDCuDmLOFiQF/AAAAIB/6sL9MO4ZwtFzwbOKNOoZxfORwNbzzHf+IpzyBTxx\r
QJcYS6QgbtSi2tUY1WeJxmq/xkMoVLgpmpK6NN+NuB6aux54U7h5B3pZ7SnoRJ7v\r
ATQnMJpwZYno8uZXhx4TmOoSxzxy2jTJb4rt4R6bbwjaI9ca/1iLavocQ218Zk20\r
4g==\r
Private-Lines: 1\r
AAAAFE5O2kb+uaE3nWLAMovNC/KYWATe\r
Private-MAC: 1b98c142780beaa5555ad5c23a0469e36f24b6f9"""


class TestKey(EmpiricalTestCase):
    """
    Unit test for SSH key generation.

    The actual test creating real keys are located in functional.
    """

    def assertBadKey(self, content, message):
        """
        Check the `content` raise a BadKeyError with `message`.
        """
        with self.assertRaises(BadKeyError) as context:
            Key.fromString(content)

        self.assertEqual(message, context.exception.message)

    def assertKeyIsTooShort(self, content):
        """
        Check the key content is too short.
        """
        self.assertBadKey(content, 'Key is too short.')

    def assertKeyParseError(self, content):
        """
        Check that key content fail to parse.
        """
        self.assertBadKey(content, 'Fail to parse key content.')

    def test_key_init_unknown_type(self):
        """
        An error is raised when generating a key with unknow type.
        """
        with self.assertRaises(KeyCertException) as context:
            key = Key(None)
            key.generate(key_type=0)
        self.assertEqual('Unknown key type "0".', context.exception.message)

    @attr('slow')
    def test_init_rsa(self):
        """
        Check generation of an RSA key.
        """
        key = Key()
        key.generate(key_type=crypto.TYPE_RSA, key_size=1024)
        self.assertEqual('RSA', key.type())
        self.assertEqual(1024, key.size)

    @attr('slow')
    def test_init_dsa(self):
        """
        Check generation of a DSA key.
        """
        key = Key()
        key.generate(key_type=crypto.TYPE_DSA, key_size=1024)
        self.assertEqual('DSA', key.type())
        self.assertEqual(1024, key.size)

    def test_key_store_rsa(self):
        """
        Check file serialization for a RSA key.
        """
        key = Key.fromString(data=OPENSSH_RSA_PRIVATE)
        public_file = StringIO()
        private_file = StringIO()
        key.store(private_file=private_file, public_file=public_file)
        self.assertEqual(OPENSSH_RSA_PRIVATE, private_file.getvalue())
        self.assertEqual(OPENSSH_RSA_PUBLIC, public_file.getvalue())

    def test_key_store_dsa(self):
        """
        Check file serialization for a DSA key.
        """
        key = Key.fromString(data=OPENSSH_DSA_PRIVATE)
        public_file = StringIO()
        private_file = StringIO()
        key.store(private_file=private_file, public_file=public_file)
        self.assertEqual(OPENSSH_DSA_PRIVATE, private_file.getvalue())
        self.assertEqual(OPENSSH_DSA_PUBLIC, public_file.getvalue())

    def test_key_store_comment(self):
        """
        When serializing a SSH public key to a file, a random comment can be
        added.
        """
        key = Key.fromString(data=OPENSSH_RSA_PUBLIC)
        public_file = StringIO()
        comment = mk.string()
        public_key_serialization = u'%s %s' % (
            OPENSSH_RSA_PUBLIC, comment)

        key.store(public_file=public_file, comment=comment)

        result_key = Key.fromString(public_file.getvalue())
        self.assertEqual(key.data, result_key.data)
        self.assertEqual(
            public_file.getvalue().decode('utf-8'), public_key_serialization)

    def test_fromString_type_unkwown(self):
        """
        An exceptions is raised when reading a key for which type could not
        be detected. Exception only contains the beginning of the content.
        """
        content = mk.ascii() * 100

        self.assertBadKey(
            content, 'Cannot guess the type for \'%s\'' % content[:80])

    def test_fromString_struct_errors(self):
        """
        Errors caused by parsing the content are raises as BadKeyError.
        """
        content = OPENSSH_DSA_PUBLIC[:32]

        self.assertKeyParseError(content)

    def test_guessStringType_unknown(self):
        """
        None is returned when could not detect key type.
        """
        sut = Key()
        content = mk.ascii()

        result = sut._guessStringType(content)

        self.assertIsNone(result)

    def test_guessStringType_private_OpenSSH(self):
        """
        Can recognize an OpenSSH private key.
        """
        sut = Key()

        result = sut._guessStringType(OPENSSH_RSA_PRIVATE)

        self.assertEqual('private_openssh', result)

    def test_guessStringType_public_OpenSSH(self):
        """
        Can recognize an OpenSSH public key.
        """
        sut = Key()

        result = sut._guessStringType(OPENSSH_RSA_PUBLIC)

        self.assertEqual('public_openssh', result)

    def test_guessStringType_private_SSHCOM(self):
        """
        Can recognize an SSH.com private key.
        """
        sut = Key()

        result = sut._guessStringType(SSHCOM_RSA_PRIVATE_NO_PASSWORD)

        self.assertEqual('private_sshcom', result)

    def test_guessStringType_public_SSHCOM(self):
        """
        Can recognize an SSH.com public key.
        """
        sut = Key()

        result = sut._guessStringType(SSHCOM_RSA_PUBLIC)

        self.assertEqual('public_sshcom', result)

    def test_guessStringType_putty(self):
        """
        Can recognize a Putty private key.
        """
        sut = Key()

        result = sut._guessStringType(PUTTY_RSA_PRIVATE_NO_PASSWORD)

        self.assertEqual('private_putty', result)

    def test_public_get(self):
        """
        Return an instance of same class but with only public elements for
        the private key.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.public()

        self.assertFalse(sut.isPublic())
        self.assertIsInstance(Key, result)
        self.assertTrue(result.isPublic())
        self.assertEqual(result.data()['e'], sut.data()['e'])
        self.assertEqual(result.data()['n'], sut.data()['n'])

    def test_fromString_PUBLIC_OPENSSH_RSA(self):
        """
        Can load public RSA OpenSSH key.
        """
        sut = Key.fromString(OPENSSH_RSA_PUBLIC)

        self.checkParsedRSAPublic1024(sut)

    def test_fromString_PUBLIC_OPENSSH_RSA_too_short(self):
        """
        An exception is raised when public RSA OpenSSH key is bad formatted.
        """
        self.assertKeyIsTooShort('ssh-rsa')

    def addSSHCOMKeyHeaders(self, source, headers):
        """
        Add headers to a SSH.com key.

        Long headers are wrapped at 70 characters.
        """
        lines = source.splitlines()
        for key, value in headers.items():
            line = '%s: %s' % (key, value.encode('utf-8'))
            header = '\\\n'.join(textwrap.wrap(line, 70))
            lines.insert(1, header)
        return '\n'.join(lines)

    def checkParsedDSAPublic1024(self, sut):
        """
        Check the default public DSA key of size 1024.

        This is a shared test for parsing DSA key from various formats.
        """
        self.assertEqual(1024, sut.size)
        self.assertEqual('DSA', sut.type())
        self.assertTrue(sut.isPublic())
        self.checkParsedDSAPublic1024Data(sut)

    def checkParsedDSAPublic1024Data(self, sut):
        """
        Check the public part values for the default DSA key of size 1024.
        """
        data = sut.data()
        self.assertEqual(long(
            '89826398702575694025672739759021185748719093895775418981133245507'
            '56542191015877768589699407493932539140865803919573940821357868468'
            '55675657634384222748339103943127442354510383477300256462657784441'
            '71019786268219332779725063911288445634960873466719023048095246499'
            '763675183656402590703132265805882271082319033570L'),
            data['y'])
        self.assertEqual(long(
            '14519098631088118929874535941241101897542246758347965800832728196'
            '81139199597265476885338795620826004398884602230901691384070382776'
            '92982149652731866793940314712388781003443391479314606037340161379'
            '86631331044475413634865132557582890274917465191550388575486379853'
            '0603422003777150811982254140040687593424378397517L'),
            data['p'])
        self.assertEqual(
            long('765629040155792319453907037659138573169171493193L'),
            data['q'])
        self.assertEqual(long(
            '64647318098084998690447943642968245369499209364165550549740815561'
            '71156388976417089337555666453157891497405105710031098879473402131'
            '15408225147127626829407642540707192214402604495716677723330515779'
            '34611656548484464881147166978432509157365635746874869548636130785'
            '946819310836368885242376237240564866586977240572L'),
            data['g'])

    def checkParsedDSAPrivate1024(self, sut):
        """
        Check the default private DSA key of size 1024.
        """
        self.assertEqual(1024, sut.size)
        self.assertEqual('DSA', sut.type())
        self.assertFalse(sut.isPublic())
        data = sut.data()
        self.checkParsedDSAPublic1024Data(sut)
        self.assertEqual(long(
            '447059752886431435417087644871194130561824720094L'),
            data['x'])

    def checkParsedRSAPublic1024(self, sut):
        """
        Check the default public RSA key of size 1024.
        """
        self.assertEqual(1024, sut.size)
        self.assertEqual('RSA', sut.type())
        self.assertTrue(sut.isPublic())
        self.checkParsedRSAPublic1024Data(sut)

    def checkParsedRSAPublic1024Data(self, sut):
        """
        Check data for public RSA key of size 1024.
        """
        data = sut.data()
        self.assertEqual(65537L, data['e'])
        self.assertEqual(long(
            '12955309129371696361961156024018278506192853914566590418922947244'
            '33008028380639675460754206681134187533029942882729688747039044313'
            '67411245192523108247958392655021595783971049572916657240822239036'
            '02442387266290082476044614892594356080524766995335587624348179950'
            '6405887692619349988915280409504938876523941259567L'),
            data['n'])

    def checkParsedRSAPrivate1024(self, sut):
        """
        Check the default private RSA key of size 1024.
        """
        self.assertEqual(1024, sut.size)
        self.assertEqual('RSA', sut.type())
        self.assertFalse(sut.isPublic())
        data = sut.data()
        self.assertEqual(65537L, data['e'])
        self.checkParsedRSAPublic1024Data(sut)
        self.assertEqual(long(
            '57010713839675255669157840568333483699071044890077432241594488384'
            '64981848192265169337649163172545274951948296799964023904757013291'
            '17313931268194522463817291948793747715146018146051093951466872189'
            '64147610108577761761364098616952641696814228146724216997423652825'
            '24517268536277980834876649127946895862158846465L'),
            data['d'])
        self.assertEqual(long(
            '10661640454627350493191065484215149934251067848734449698668476614'
            '18981319570111200535213963399376281314470995958266981264747210946'
            '6364885923117389812635119L'),
            data['p'])
        self.assertEqual(long(
            '12151328104249520956550929707892880056509323657595783040548358917'
            '98785549316902458371621691657702435263762556929800891556172971312'
            '6473919204485168003686593L'),
            data['q'])
        self.assertEqual(long(
            '66777727502990278851698381429390065987141247478987840061938912337'
            '88877413103516203638312270220327073357315389300205491590285175084'
            '040066037688353071226161L'),
            data['u'])

    def test_fromString_PUBLIC_SSHCOM_RSA_no_headers(self):
        """
        Can load a public RSA SSH.com key which has no headers.
        """
        sut = Key.fromString(SSHCOM_RSA_PUBLIC)

        self.checkParsedRSAPublic1024(sut)

    def test_fromString_PUBLIC_SSHCOM_RSA_public_headers(self):
        """
        Can import a public RSA SSH.com key with headers.
        """
        key_content = self.addSSHCOMKeyHeaders(
            source=SSHCOM_RSA_PUBLIC,
            headers={
                'Comment': '"short comment"',
                'Subject': 'Very very long subject' * 10,
                'x-private': mk.string(),
                },
            )
        sut = Key.fromString(key_content)

        self.assertEqual(1024, sut.size)
        self.assertEqual('RSA', sut.type())
        self.assertTrue(sut.isPublic())
        data = sut.data()
        self.assertEqual(65537L, data['e'])

    def test_fromString_PUBLIC_OPENSSH_DSA(self):
        """
        Can load a public OpenSSH in DSA format.
        """
        sut = Key.fromString(OPENSSH_DSA_PUBLIC)

        self.checkParsedDSAPublic1024(sut)

    def test_fromString_PUBLIC_SSHCOM_DSA(self):
        """
        Can load a public SSH.com in DSA format.
        """
        sut = Key.fromString(SSHCOM_DSA_PUBLIC)

        self.checkParsedDSAPublic1024(sut)

    def test_fromString_PUBLIC_SSHCOM_short(self):
        """
        Raise an exception when key is too short.
        """
        content = '---- BEGIN SSH2 PUBLIC KEY ----'

        self.assertKeyParseError(content)

        content = '---- BEGIN SSH2 PUBLIC KEY ----\nnext line'

        self.assertKeyParseError(content)

    def test_fromString_PUBLIC_SSHCOM_RSA_invalid_payload(self):
        """
        Raise an exception when key has a bad format.
        """
        content = """---- BEGIN SSH2 PUBLIC KEY ----
AAAAB3NzaC1yc2EA
---- END SSH2 PUBLIC KEY ----"""

        self.assertKeyParseError(content)

    def test_toString_SSHCOM_RSA_public_no_headers(self):
        """
        Can export a public RSA SSH.com key with headers.
        """
        sut = Key.fromString(OPENSSH_RSA_PUBLIC)

        result = sut.toString(type='sshcom')

        self.assertEqual(SSHCOM_RSA_PUBLIC, result)

    def test_toString_SSHCOM_RSA_public_with_comment(self):
        """
        Can export a public RSA SSH.com key with headers.
        """
        sut = Key.fromString(OPENSSH_RSA_PUBLIC)
        comment = mk.string() * 20

        result = sut.toString(type='sshcom', extra=comment)

        expected = self.addSSHCOMKeyHeaders(
            source=SSHCOM_RSA_PUBLIC,
            headers={'Comment': '"%s"' % comment},
            )
        self.assertEqual(expected, result)

    def test_toString_SSHCOM_DSA_public(self):
        """
        Can export a public DSA SSH.com key.
        """
        sut = Key.fromString(OPENSSH_DSA_PUBLIC)

        result = sut.toString(type='sshcom')

        self.assertEqual(SSHCOM_DSA_PUBLIC, result)

    def test_fromString_PRIVATE_OPENSSH_RSA(self):
        """
        Can load a private OpenSSH RSA key.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_OPENSSH_DSA(self):
        """
        Can load a private OpenSSH DSA key.
        """
        sut = Key.fromString(OPENSSH_DSA_PRIVATE)

        self.checkParsedDSAPrivate1024(sut)

    def test_fromString_PRIVATE_OPENSSH_short(self):
        """
        Raise an error when private OpenSSH key is too short.
        """
        content = '-----BEGIN RSA PRIVATE KEY-----'

        self.assertKeyIsTooShort(content)

        content = '-----BEGIN RSA PRIVATE KEY-----\nAnother Line'

        self.assertBadKey(content, 'Failed to decode key')

    def test_fromString_PRIVATE_OPENSSH_bad_encoding(self):
        """
        Raise an error when private OpenSSH key data can not be decoded.
        """
        content = '-----BEGIN RSA PRIVATE KEY-----\nAnother Line\nLast'

        self.assertKeyParseError(content)

    def test_fromString_PRIVATE_SSHCOM_RSA_no_headers_no_password(self):
        """
        Can load a private SSH.com key which has no headers and no password.
        """
        sut = Key.fromString(SSHCOM_RSA_PRIVATE_NO_PASSWORD)

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_SSHCOM_RSA_encrypted(self):
        """
        Can load a private SSH.com key encrypted with password`.
        """
        sut = Key.fromString(
            SSHCOM_RSA_PRIVATE_WITH_PASSWORD, passphrase='chevah')

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_SSHCOM_DSA_no_password(self):
        """
        Can load a private SSH.com in DSA format.
        """
        sut = Key.fromString(SSHCOM_DSA_PRIVATE_NO_PASSWORD)

        self.checkParsedDSAPrivate1024(sut)

    def test_fromString_PRIVATE_SSHCOM_short(self):
        """
        Raise an exception when private key is too short.
        """
        content = '---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----'

        self.assertKeyParseError(content)

        content = '---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nnext line'

        self.assertKeyParseError(content)

    def test_fromString_PRIVATE_SSHCOM_RSA_encrypted_no_password(self):
        """
        An exceptions is raised whey trying to load a private SSH.com key
        which is encrypted, but without providing a password.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(SSHCOM_RSA_PRIVATE_WITH_PASSWORD)

        self.assertEqual(
            'Passphrase must be provided for an encrypted key.',
            context.exception.message)

    def test_fromString_PRIVATE_SSHCOM_RSA_with_wrong_password(self):
        """
        An exceptions is raised whey trying to load a private SSH.com key
        which is encrypted, but providing a wrong password.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(SSHCOM_RSA_PRIVATE_WITH_PASSWORD, passphrase='on')

        self.assertEqual(
            'Bad password or bad key format.',
            context.exception.message)

    def test_fromString_PRIVATE_OPENSSH_bad_magic(self):
        """
        Exception is raised when key data does not start with the key marker.
        """
        content = """---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
B2/56wAAAi4AAAA3
---- END SSH2 ENCRYPTED PRIVATE KEY ----"""

        self.assertBadKey(
            content, 'Bad magic number for SSH.com key 124778987')

    def test_fromString_PRIVATE_OPENSSH_bad_key_type(self):
        """
        Exception is raised when key has an unknown type.
        """
        content = """---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
P2/56wAAAi4AAAA3aWYtbW9kbntzaW==
---- END SSH2 ENCRYPTED PRIVATE KEY ----"""

        self.assertBadKey(content, 'Unknown SSH.com key type if-modn{si')

    def test_fromString_PRIVATE_OPENSSH_bad_structure(self):
        """
        Exception is raised when key has no valid parts, ie too short.
        """
        content = """---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
P2/56wAAAi4AAAA3aWYtbW9kbntzaWdue3JzYS1wa2NzMS1zaGExfSxlbmNyeXB0e3JzYS
1wa2NzMXYyLW9hZXB9fQAAAARub25l
---- END SSH2 ENCRYPTED PRIVATE KEY ----"""

        self.assertKeyParseError(content)

    def test_toString_SSHCOM_RSA_private_without_encryption(self):
        """
        Can export a private RSA SSH.com without without encryption.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type='sshcom')

        # Check that it looks like SSH.com private key.
        self.assertEqual(SSHCOM_RSA_PRIVATE_NO_PASSWORD, result)
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_SSHCOM_RSA_private_encrypted(self):
        """
        Can export an encrypted private RSA SSH.com.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type='sshcom', extra='chevah')

        # Check that it looks like SSH.com private key.
        self.assertEqual(SSHCOM_RSA_PRIVATE_WITH_PASSWORD, result)
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result, passphrase='chevah')
        self.assertEqual(sut, reloaded)

    def test_toString_SSHCOM_DSA_private(self):
        """
        Can export a private DSA SSH.com key.
        """
        sut = Key.fromString(OPENSSH_DSA_PRIVATE)

        result = sut.toString(type='sshcom')

        self.assertEqual(SSHCOM_DSA_PRIVATE_NO_PASSWORD, result)
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_fromString_PRIVATE_PUTTY_RSA_no_password(self):
        """
        It can read private RSA keys in Putty format which are not
        encrypted.
        """
        sut = Key.fromString(PUTTY_RSA_PRIVATE_NO_PASSWORD)

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_RSA_with_password(self):
        """
        It can read private RSA keys in Putty format which are encrypted.
        """
        sut = Key.fromString(
            PUTTY_RSA_PRIVATE_WITH_PASSWORD, passphrase='chevah')

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_short(self):
        """
        An exception is raised when key is too short.
        """
        content = 'PuTTY-User-Key-File-2: ssh-rsa'

        self.assertKeyIsTooShort(content)

        content = (
            'PuTTY-User-Key-File-2: ssh-rsa\n'
            'Encryption: aes256-cbc\n'
            )

        self.assertKeyIsTooShort(content)

        content = (
            'PuTTY-User-Key-File-2: ssh-rsa\n'
            'Encryption: aes256-cbc\n'
            'Comment: bla\n'
            )

        self.assertKeyIsTooShort(content)

    def test_fromString_PRIVATE_PUTTY_RSA_bad_password(self):
        """
        An exception is raised when password is not valid.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(
                PUTTY_RSA_PRIVATE_WITH_PASSWORD, passphrase='bad-pass')

        self.assertEqual(
            'Bad password or HMAC mismatch.', context.exception.message)

    def test_fromString_PRIVATE_PUTTY_RSA_missing_password(self):
        """
        An exception is raised when key is encrypted but no password was
        provided.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(PUTTY_RSA_PRIVATE_WITH_PASSWORD)

        self.assertEqual(
            'Passphrase must be provided for an encrypted key.',
            context.exception.message)

    def test_fromString_PRIVATE_PUTTY_unsupported_type(self):
        """
        An exception is raised when key contain a type which is not supported.
        """
        content = """PuTTY-User-Key-File-2: ssh-bad
IGNORED
"""
        self.assertBadKey(
            content, 'Unsupported key type: ssh-bad')

    def test_fromString_PRIVATE_PUTTY_unsupported_encryption(self):
        """
        An exception is raised when key contain an encryption method
        which is not supported.
        """
        content = """PuTTY-User-Key-File-2: ssh-dss
Encryption: aes126-cbc
IGNORED
"""
        self.assertBadKey(
            content, 'Unsupported encryption type: aes126-cbc')

    def test_fromString_PRIVATE_PUTTY_type_mismatch(self):
        """
        An exception is raised when key header advertise one key type while
        the public key another.
        """
        content = """PuTTY-User-Key-File-2: ssh-rsa
Encryption: aes256-cbc
Comment: imported-openssh-key
Public-Lines: 4
AAAAB3NzaC1kc3MAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTK
APkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk
+X6Lc4+lAfp1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcj
RToF6/jpLw==
IGNORED
"""
        self.assertBadKey(
            content,
            'Mismatch key type. Header has ssh-rsa, public has ssh-dss',
            )

    def test_fromString_PRIVATE_PUTTY_hmac_mismatch(self):
        """
        An exception is raised when key HMAC differs from the one
        advertise by the key file.
        """
        content = PUTTY_RSA_PRIVATE_NO_PASSWORD[:-1]
        content += 'a'

        self.assertBadKey(
            content,
            'HMAC mismatch: file declare '
            '7630b86be300c6302ce1390fb264487bb61e67ca, actual is '
            '7630b86be300c6302ce1390fb264487bb61e67ce',
            )

    def test_fromString_PRIVATE_OpenSSH_DSA_no_password(self):
        """
        It can read private DSA keys in OpenSSH format.
        """
        sut = Key.fromString(OPENSSH_DSA_PRIVATE)

        self.checkParsedDSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_DSA_no_password(self):
        """
        It can read private DSA keys in Putty format which are not
        encrypted.
        """
        sut = Key.fromString(PUTTY_DSA_PRIVATE_NO_PASSWORD)

        self.checkParsedDSAPrivate1024(sut)

    def test_toString_PUTTY_RSA_plain(self):
        """
        Can export to private RSA Putty without encryption.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type='putty')

        # We can not check the exact text as comment is hardcoded in
        # Twisted.
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_RSA_encrypted(self):
        """
        Can export to encrypted private RSA Putty key.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type='putty', extra='write-pass')

        # We can not check the exact text as comment is hardcoded in
        # Twisted.
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result, passphrase='write-pass')
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_DSA_plain(self):
        """
        Can export to private DSA Putty key without encryption.
        """
        sut = Key.fromString(OPENSSH_DSA_PRIVATE)

        result = sut.toString(type='putty')

        # We can not check the exact text as comment is hardcoded in
        # Twisted.
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)


class DummyKey(object):
    """
    Helper for testing operations on SSH keys.
    """

    def __init__(self):
        self.generate = Mock()
        self.store = Mock()


class DummyOpenContext(object):
    """
    Helper for testing operations using open context manager.

    It keeps a record or all calls in self.calls.
    """

    def __init__(self):
        self.calls = []

    def __call__(self, path, mode):
        self.calls.append({'path': path, 'mode': mode})
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        return False


class TestCryptoHelpers(EmpiricalTestCase):
    """
    Unit tests for crypto helpers.
    """

    def test_generate_ssh_key_custom_values(self):
        """
        When custom values are provided, the key is generated using those
        values.
        """
        options = self.Bunch(
            migrate=False,
            key_size=2048,
            key_type=u'DSA',
            key_file=u'test_file',
            key_comment=u'this is a comment',
            )
        key = DummyKey()
        open_method = DummyOpenContext()

        exit_code, message = generate_ssh_key(
            options, key=key, open_method=open_method)

        # Key is generated with requested type and length.
        key.generate.assert_called_once_with(
            key_type=crypto.TYPE_DSA, key_size=2048)
        # Both keys are stored. The public key has the specified comment.
        self.assertEqual(2, key.store.call_count)
        key.store.assert_has_calls([
            call(private_file=open_method),
            call(public_file=open_method, comment=u'this is a comment'),
            ])
        # First it writes the private key.
        self.assertEqual(
            {'path': 'test_file', 'mode': 'wb'}, open_method.calls[0])
        # Then it writes the public key.
        self.assertEqual(
            {'path': 'test_file.pub', 'mode': 'wb'}, open_method.calls[1])
        self.assertEqual(
            u'SSH key of type "DSA" and length "2048" generated as public '
            u'key file "test_file.pub" and private key file "test_file" '
            u'having comment "this is a comment".',
            message,
            )
        self.assertEqual(0, exit_code)

    def test_generate_ssh_key_default_values(self):
        """
        When no path and no comment are provided, it will use default
        values.
        """
        options = self.Bunch(
            migrate=False,
            key_size=1024,
            key_type=u'RSA'
            )
        key = DummyKey()
        open_method = DummyOpenContext()

        exit_code, message = generate_ssh_key(
            options, key=key, open_method=open_method)

        # Writes private key and public key without a comment.
        key.store.assert_has_calls([
            call(private_file=open_method),
            call(public_file=open_method, comment=None),
            ])
        # Default file path is used for private and public keys.
        self.assertEqual(
            {'path': 'id_rsa', 'mode': 'wb'}, open_method.calls[0])
        self.assertEqual(
            {'path': 'id_rsa.pub', 'mode': 'wb'}, open_method.calls[1])
        # Message informs what default values were used.
        self.assertEqual(
            u'SSH key of type "RSA" and length "1024" generated as public '
            u'key file "id_rsa.pub" and private key file "id_rsa" without '
            u'a comment.',
            message,
            )

    def test_generate_ssh_key_private_exist_no_migration(self):
        """
        When no migration is done it will not generate the key,
        if private file already exists and exit with error.
        """
        self.test_segments = mk.fs.createFileInTemp()
        path = mk.fs.getRealPathFromSegments(self.test_segments)
        options = self.Bunch(
            migrate=False,
            key_type=u'RSA',
            key_size=2048,
            key_file=path,
            )
        open_method = DummyOpenContext()

        exit_code, message = generate_ssh_key(
            options, key=None, open_method=open_method)

        self.assertEqual(1, exit_code)
        self.assertEqual(u'Private key already exists. %s' % path, message)
        # Open is not called.
        self.assertIsEmpty(open_method.calls)

    def test_generate_ssh_key_private_exist_migrate(self):
        """
        On migration, will not generate the key, if private file already
        exists and exit without error.
        """
        self.test_segments = mk.fs.createFileInTemp()
        path = mk.fs.getRealPathFromSegments(self.test_segments)
        options = self.Bunch(
            migrate=True,
            key_type=u'RSA',
            key_size=2048,
            key_file=path,
            )
        open_method = DummyOpenContext()

        exit_code, message = generate_ssh_key(
            options, key=None, open_method=open_method)

        self.assertEqual(0, exit_code)
        self.assertEqual(u'Key already exists.', message)
        # Open is not called.
        self.assertIsEmpty(open_method.calls)

    def test_generate_ssh_key_public_exist(self):
        """
        Will not generate the key, if public file already exists.
        """
        self.test_segments = mk.fs.createFileInTemp(suffix='.pub')
        path = mk.fs.getRealPathFromSegments(self.test_segments)
        options = self.Bunch(
            migrate=False,
            key_type=u'RSA',
            key_size=2048,
            # path is for public key, but we pass the private path.
            key_file=path[:-4],
            )
        open_method = DummyOpenContext()

        exit_code, message = generate_ssh_key(
            options, key=None, open_method=open_method)

        self.assertEqual(1, exit_code)
        self.assertEqual(u'Public key already exists. %s' % path, message)
        # Open is not called.
        self.assertIsEmpty(open_method.calls)
