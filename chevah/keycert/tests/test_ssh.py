# Copyright (c) 2014 Adi Roiban.
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
Test for SSH keys management.
"""
from __future__ import absolute_import, division

from argparse import ArgumentParser
from StringIO import StringIO
import base64
import textwrap

from chevah.compat.testing import mk, ChevahTestCase
from nose.plugins.attrib import attr

# Twisted test compatibility.
from chevah.keycert import ssh as keys, common, sexpy
from chevah.keycert.exceptions import (
    BadKeyError,
    KeyCertException,
    EncryptedKeyError,
    )
from chevah.keycert.ssh import (
    Key,
    generate_ssh_key,
    generate_ssh_key_parser,
    )
from chevah.keycert.tests import keydata
from chevah.keycert.tests.helpers import CommandLineMixin

PUBLIC_RSA_ARMOR_START = u'-----BEGIN PUBLIC KEY-----\n'
PUBLIC_RSA_ARMOR_END = u'\n-----END PUBLIC KEY-----\n'
PRIVATE_RSA_ARMOR_START = u'-----BEGIN RSA PRIVATE KEY-----\n'
PRIVATE_RSA_ARMOR_END = u'\n-----END RSA PRIVATE KEY-----\n'
PUBLIC_DSA_ARMOR_START = u'-----BEGIN PUBLIC KEY-----\n'
PUBLIC_DSA_ARMOR_END = u'\n-----END PUBLIC KEY-----\n'
PRIVATE_DSA_ARMOR_START = u'-----BEGIN DSA PRIVATE KEY-----\n'
PRIVATE_DSA_ARMOR_END = u'\n-----END DSA PRIVATE KEY-----\n'

OPENSSH_RSA_PRIVATE = """-----BEGIN RSA PRIVATE KEY-----
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
/RTFeEyTOiWL4CLQCwJAW7JDG5psx0rZPFgPTzX81FhiwjhCfI/WwBnmiZyGDc1R
REFRtKobm6r5pIDYrjBK1R05/D2otwJVdy3JVUO+sQ==
-----END RSA PRIVATE KEY-----"""

# Same as OPENSSH_RSA_PRIVATE but in the old OpenSSH format.
# `p` and `q` parameters are reversed.
OPENSSH_RSA_PRIVATE_OLD = ('''-----BEGIN RSA PRIVATE KEY-----
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
# Generated using:
# puttygen test-ssh-rsa-1024 -O private -o putty-1020.ppk -C COMMENT
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

# Same as   , with 'chevah' password.
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


class DummyOpenContext(object):
    """
    Helper for testing operations using open context manager.

    It keeps a record or all calls in self.calls.
    """

    def __init__(self):
        self.calls = []
        self.last_stream = None

    def __call__(self, path, mode):
        self.last_stream = StringIO()
        self.calls.append(
            {'path': path, 'mode': mode, 'stream': self.last_stream})
        return self

    def __enter__(self):
        return self.last_stream

    def __exit__(self, exc_type, exc_value, tb):
        return False


class NonRandomBytes(object):
    """
    A replacement for `randbytes` to help with testing.
    """

    @staticmethod
    def secureRandom(x):
        return '\xff' * x


class TestKey(ChevahTestCase):
    """
    Unit test for SSH key generation.

    The actual test creating real keys are located in functional.
    """

    def setUp(self):
        super(TestKey, self).setUp()
        self.rsaObj = keys.Key._fromRSAComponents(
            n=keydata.RSAData['n'],
            e=keydata.RSAData['e'],
            d=keydata.RSAData['d'],
            p=keydata.RSAData['p'],
            q=keydata.RSAData['q'],
            u=keydata.RSAData['u'],
            )._keyObject
        self.dsaObj = keys.Key._fromDSAComponents(
            y=keydata.DSAData['y'],
            p=keydata.DSAData['p'],
            q=keydata.DSAData['q'],
            g=keydata.DSAData['g'],
            x=keydata.DSAData['x'],
            )._keyObject
        self.ecObj = keys.Key._fromECComponents(
            x=keydata.ECDatanistp256['x'],
            y=keydata.ECDatanistp256['y'],
            privateValue=keydata.ECDatanistp256['privateValue'],
            curve=keydata.ECDatanistp256['curve']
        )._keyObject
        self.ecObj384 = keys.Key._fromECComponents(
            x=keydata.ECDatanistp384['x'],
            y=keydata.ECDatanistp384['y'],
            privateValue=keydata.ECDatanistp384['privateValue'],
            curve=keydata.ECDatanistp384['curve']
        )._keyObject
        self.ecObj521 = keys.Key._fromECComponents(
            x=keydata.ECDatanistp521['x'],
            y=keydata.ECDatanistp521['y'],
            privateValue=keydata.ECDatanistp521['privateValue'],
            curve=keydata.ECDatanistp521['curve']
        )._keyObject
        self.rsaSignature = (
            b"\x00\x00\x00\x07ssh-rsa\x00\x00\x01\x00~Y\xa3\xd7\xfdW\xc6pu@"
            b"\xd81\xa1S\xf3O\xdaE\xf4/\x1ex\x1d\xf1\x9a\xe1G3\xd9\xd6U\x1f"
            b"\x8c\xd9\x1b\x8b\x90\x0e\x8a\xc1\x91\xd8\x0cd\xc9\x0c\xe7\xb2"
            b"\xc9,'=\x15\x1cQg\xe7x\xb5j\xdbI\xc0\xde\xafb\xd7@\xcar\x0b"
            b"\xce\xa3zM\x151q5\xde\xfa\x0c{wjKN\x88\xcbC\xe5\x89\xc3\xf9i"
            b"\x96\x91\xdb\xca}\xdbR\x1a\x13T\xf9\x0cDJH\x0b\x06\xcfl\xf3"
            b"\x13[\x82\xa2\x9d\x93\xfd\x8e\xce|\xfb^n\xd4\xed\xe2\xd1\x8a"
            b"\xb7aY\x9bB\x8f\xa4\xc7\xbe7\xb5\x0b9j\xa4.\x87\x13\xf7\xf0"
            b"\xda\xd7\xd2\xf9\x1f9p\xfd?\x18\x0f\xf2N\x9b\xcf/\x1e)\n>A\x19"
            b"\xc2\xb5j\xf9UW\xd4\xae\x87B\xe6\x99t\xa2y\x90\x98\xa2\xaaf\xcb"
            b"\x86\xe5k\xe3\xce\xe0u\x1c\xeb\x93\x1aN\x88\xc9\x93Y\xc3.V\xb1L"
            b"44`C\xc7\xa66\xaf\xfa\x7f\x04Y\x92\xfa\xa4\x1a\x18%\x19\xd5 4^"
            b"\xb9rY\xba \x01\xf9.\x89%H\xbe\x1c\x83A\x96"
        )
        self.dsaSignature = (
            b'\x00\x00\x00\x07ssh-dss\x00\x00\x00(?\xc7\xeb\x86;\xd5TFA\xb4'
            b'\xdf\x0c\xc4E@4,d\xbc\t\xd9\xae\xdd[\xed-\x82nQ\x8cf\x9b\xe8\xe1'
            b'jrg\x84p<'
        )
        self.oldrandbytes = keys.randbytes
        keys.randbytes = NonRandomBytes()

    def tearDown(self):
        keys.randbytes = self.oldrandbytes
        super(TestKey, self).tearDown()

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

    def _testPublicPrivateFromString(self, public, private, type, data):
        self._testPublicFromString(public, type, data)
        self._testPrivateFromString(private, type, data)

    def _testPublicFromString(self, public, type, data):
        publicKey = keys.Key.fromString(public)
        self.assertTrue(publicKey.isPublic())
        self.assertEqual(publicKey.type(), type)
        for k, v in publicKey.data().items():
            self.assertEqual(data[k], v)

    def _testPrivateFromString(self, private, type, data):
        privateKey = keys.Key.fromString(private)
        self.assertFalse(privateKey.isPublic())
        self.assertEqual(privateKey.type(), type)
        for k, v in data.items():
            self.assertEqual(
                privateKey.data()[k], v,
                'Mismatch at %s\n %s != %s' % (k, privateKey.data()[k], v))

    def test_size(self):
        """
        The L{keys.Key.size} method returns the size of key object in bits.
        """
        self.assertEqual(keys.Key(self.rsaObj).size(), 2048)
        self.assertEqual(keys.Key(self.dsaObj).size(), 1024)
        self.assertEqual(keys.Key(self.ecObj).size(), 256)
        self.assertEqual(keys.Key(self.ecObj384).size(), 384)
        self.assertEqual(keys.Key(self.ecObj521).size(), 521)

    def test_guessStringType(self):
        """
        Test that the _guessStringType method guesses string types
        correctly.

        Imported from Twisted.
        """
        self.assertEqual(
            keys.Key._guessStringType(keydata.publicRSA_openssh),
            'public_openssh')
        self.assertEqual(
            keys.Key._guessStringType(keydata.publicDSA_openssh),
            'public_openssh')
        self.assertEqual(
            keys.Key._guessStringType(
                keydata.privateRSA_openssh),
            'private_openssh')
        self.assertEqual(
            keys.Key._guessStringType(
                keydata.privateDSA_openssh),
            'private_openssh')
        self.assertEqual(
            keys.Key._guessStringType(keydata.publicRSA_lsh),
            'public_lsh')
        self.assertEqual(
            keys.Key._guessStringType(keydata.publicDSA_lsh),
            'public_lsh')
        self.assertEqual(
            keys.Key._guessStringType(keydata.privateRSA_lsh),
            'private_lsh')
        self.assertEqual(
            keys.Key._guessStringType(keydata.privateDSA_lsh),
            'private_lsh')
        self.assertEqual(
            keys.Key._guessStringType(
                keydata.privateRSA_agentv3),
            'agentv3')
        self.assertEqual(
            keys.Key._guessStringType(
                keydata.privateDSA_agentv3),
            'agentv3')
        self.assertEqual(
            keys.Key._guessStringType(
                '\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01\x01'),
            'blob')
        self.assertEqual(
            keys.Key._guessStringType(
                '\x00\x00\x00\x07ssh-dss\x00\x00\x00\x01\x01'),
            'blob')
        self.assertEqual(
            keys.Key._guessStringType('not a key'),
            None)

    def test_public(self):
        """
        The L{keys.Key.public} method returns a public key for both
        public and private keys.
        """
        # NB: This assumes that the private and public keys correspond
        # to each other.
        privateRSAKey = keys.Key.fromString(keydata.privateRSA_openssh)
        publicRSAKey = keys.Key.fromString(keydata.publicRSA_openssh)
        self.assertEqual(privateRSAKey.public(), publicRSAKey.public())

        privateDSAKey = keys.Key.fromString(keydata.privateDSA_openssh)
        publicDSAKey = keys.Key.fromString(keydata.publicDSA_openssh)
        self.assertEqual(privateDSAKey.public(), publicDSAKey.public())

        privateECDSAKey = keys.Key.fromString(keydata.privateECDSA_openssh)
        publicECDSAKey = keys.Key.fromString(keydata.publicECDSA_openssh)
        self.assertEqual(privateECDSAKey.public(), publicECDSAKey.public())

    def test_isPublic(self):
        """
        The L{keys.Key.isPublic} method returns True for public keys
        otherwise False.
        """
        rsaKey = keys.Key.fromString(keydata.privateRSA_openssh)
        dsaKey = keys.Key.fromString(keydata.privateDSA_openssh)
        ecdsaKey = keys.Key.fromString(keydata.privateECDSA_openssh)
        self.assertTrue(rsaKey.public().isPublic())
        self.assertFalse(rsaKey.isPublic())
        self.assertTrue(dsaKey.public().isPublic())
        self.assertFalse(dsaKey.isPublic())
        self.assertTrue(ecdsaKey.public().isPublic())
        self.assertFalse(ecdsaKey.isPublic())

    def test_fromOpenSSH(self):
        """
        Test that keys are correctly generated from OpenSSH strings.
        """
        self._testPublicPrivateFromString(keydata.publicECDSA_openssh,
                keydata.privateECDSA_openssh, 'EC', keydata.ECDatanistp256)
        self._testPublicPrivateFromString(keydata.publicRSA_openssh,
                keydata.privateRSA_openssh, 'RSA', keydata.RSAData)
        self.assertEqual(keys.Key.fromString(
            keydata.privateRSA_openssh_encrypted,
            passphrase=b'encrypted'),
            keys.Key.fromString(keydata.privateRSA_openssh))
        self.assertEqual(keys.Key.fromString(
            keydata.privateRSA_openssh_alternate),
            keys.Key.fromString(keydata.privateRSA_openssh))
        self._testPublicPrivateFromString(keydata.publicDSA_openssh,
                keydata.privateDSA_openssh, 'DSA', keydata.DSAData)

    def test_fromOpenSSHErrors(self):
        """
        Tests for invalid key types.
        """
        badKey = b"""-----BEGIN FOO PRIVATE KEY-----
MIGkAgEBBDAtAi7I8j73WCX20qUM5hhHwHuFzYWYYILs2Sh8UZ+awNkARZ/Fu2LU
LLl5RtOQpbWgBwYFK4EEACKhZANiAATU17sA9P5FRwSknKcFsjjsk0+E3CeXPYX0
Tk/M0HK3PpWQWgrO8JdRHP9eFE9O/23P8BumwFt7F/AvPlCzVd35VfraFT0o4cCW
G0RqpQ+np31aKmeJshkcYALEchnU+tQ=
-----END EC PRIVATE KEY-----"""
        self.assertRaises(keys.BadKeyError,
            keys.Key._fromString_PRIVATE_OPENSSH, badKey, None)

    def test_fromOpenSSH_with_whitespace(self):
        """
        If key strings have trailing whitespace, it should be ignored.
        """
        # from bug #3391, since our test key data doesn't have
        # an issue with appended newlines
        privateDSAData = b"""-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDylESNuc61jq2yatCzZbenlr9llG+p9LhIpOLUbXhhHcwC6hrh
EZIdCKqTO0USLrGoP5uS9UHAUoeN62Z0KXXWTwOWGEQn/syyPzNJtnBorHpNUT9D
Qzwl1yUa53NNgEctpo4NoEFOx8PuU6iFLyvgHCjNn2MsuGuzkZm7sI9ZpQIVAJiR
9dPc08KLdpJyRxz8T74b4FQRAoGAGBc4Z5Y6R/HZi7AYM/iNOM8su6hrk8ypkBwR
a3Dbhzk97fuV3SF1SDrcQu4zF7c4CtH609N5nfZs2SUjLLGPWln83Ysb8qhh55Em
AcHXuROrHS/sDsnqu8FQp86MaudrqMExCOYyVPE7jaBWW+/JWFbKCxmgOCSdViUJ
esJpBFsCgYEA7+jtVvSt9yrwsS/YU1QGP5wRAiDYB+T5cK4HytzAqJKRdC5qS4zf
C7R0eKcDHHLMYO39aPnCwXjscisnInEhYGNblTDyPyiyNxAOXuC8x7luTmwzMbNJ
/ow0IqSj0VF72VJN9uSoPpFd4lLT0zN8v42RWja0M8ohWNf+YNJluPgCFE0PT4Vm
SUrCyZXsNh6VXwjs3gKQ
-----END DSA PRIVATE KEY-----"""
        self.assertEqual(keys.Key.fromString(privateDSAData),
                         keys.Key.fromString(privateDSAData + b'\n'))

    def test_fromNewerOpenSSH(self):
        """
        Newer versions of OpenSSH generate encrypted keys which have a longer
        IV than the older versions.  These newer keys are also loaded.
        """
        key = keys.Key.fromString(keydata.privateRSA_openssh_encrypted_aes,
                                  passphrase=b'testxp')
        self.assertEqual(key.type(), 'RSA')
        key2 = keys.Key.fromString(
            keydata.privateRSA_openssh_encrypted_aes + b'\n',
            passphrase=b'testxp')
        self.assertEqual(key, key2)

    def test_fromOpenSSH_v1_format(self):
        """
        OpenSSH 6.5 introduced a newer "openssh-key-v1" private key format
        (made the default in OpenSSH 7.8).  Loading keys in this format
        produces identical results to loading the same keys in the old
        PEM-based format.
        """
        for old, new in (
                (keydata.privateRSA_openssh, keydata.privateRSA_openssh_new),
                (keydata.privateDSA_openssh, keydata.privateDSA_openssh_new),
                (keydata.privateECDSA_openssh,
                 keydata.privateECDSA_openssh_new),
                (keydata.privateECDSA_openssh384,
                 keydata.privateECDSA_openssh384_new),
                (keydata.privateECDSA_openssh521,
                 keydata.privateECDSA_openssh521_new)):
            self.assertEqual(
                keys.Key.fromString(new), keys.Key.fromString(old))
        self.assertEqual(
            keys.Key.fromString(
                keydata.privateRSA_openssh_encrypted_new,
                passphrase=b'encrypted'),
            keys.Key.fromString(
                keydata.privateRSA_openssh_encrypted,
                passphrase=b'encrypted'))

    def test_fromOpenSSH_windows_line_endings(self):
        """
        Test that keys are correctly generated from OpenSSH strings with
        Windows line endings.
        """
        privateDSAData = b"""-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDylESNuc61jq2yatCzZbenlr9llG+p9LhIpOLUbXhhHcwC6hrh
EZIdCKqTO0USLrGoP5uS9UHAUoeN62Z0KXXWTwOWGEQn/syyPzNJtnBorHpNUT9D
Qzwl1yUa53NNgEctpo4NoEFOx8PuU6iFLyvgHCjNn2MsuGuzkZm7sI9ZpQIVAJiR
9dPc08KLdpJyRxz8T74b4FQRAoGAGBc4Z5Y6R/HZi7AYM/iNOM8su6hrk8ypkBwR
a3Dbhzk97fuV3SF1SDrcQu4zF7c4CtH609N5nfZs2SUjLLGPWln83Ysb8qhh55Em
AcHXuROrHS/sDsnqu8FQp86MaudrqMExCOYyVPE7jaBWW+/JWFbKCxmgOCSdViUJ
esJpBFsCgYEA7+jtVvSt9yrwsS/YU1QGP5wRAiDYB+T5cK4HytzAqJKRdC5qS4zf
C7R0eKcDHHLMYO39aPnCwXjscisnInEhYGNblTDyPyiyNxAOXuC8x7luTmwzMbNJ
/ow0IqSj0VF72VJN9uSoPpFd4lLT0zN8v42RWja0M8ohWNf+YNJluPgCFE0PT4Vm
SUrCyZXsNh6VXwjs3gKQ
-----END DSA PRIVATE KEY-----"""
        self.assertEqual(
            keys.Key.fromString(privateDSAData),
            keys.Key.fromString(privateDSAData.replace(b'\n', b'\r\n')))

    def test_fromLSHPublicUnsupportedType(self):
        """
        C{BadKeyError} exception is raised when public key has an unknown
        type.
        """
        sexp = sexpy.pack([[b'public-key', [b'bad-key', [b'p', b'2']]]])

        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString, data=b'{' + base64.encodestring(sexp) + b'}',
            )

    def test_fromLSHPrivateUnsupportedType(self):
        """
        C{BadKeyError} exception is raised when private key has an unknown
        type.
        """
        sexp = sexpy.pack([[b'private-key', [b'bad-key', [b'p', b'2']]]])

        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString, sexp,
            )

    def test_fromLSHRSA(self):
        """
        RSA public and private keys can be generated from a LSH strings.
        """
        self._testPublicPrivateFromString(
            keydata.publicRSA_lsh,
            keydata.privateRSA_lsh,
            'RSA',
            keydata.RSAData,
            )

    def test_fromLSHDSA(self):
        """
        DSA public and private key can be generated from LSHs.
        """
        self._testPublicPrivateFromString(
            keydata.publicDSA_lsh,
            keydata.privateDSA_lsh,
            'DSA',
            keydata.DSAData,
            )

    def test_fromAgentv3(self):
        """
        Test that keys are correctly generated from Agent v3 strings.
        """
        self._testPrivateFromString(keydata.privateRSA_agentv3, 'RSA',
                keydata.RSAData)
        self._testPrivateFromString(keydata.privateDSA_agentv3, 'DSA',
                keydata.DSAData)
        self.assertRaises(keys.BadKeyError, keys.Key.fromString,
                b'\x00\x00\x00\x07ssh-foo' + b'\x00\x00\x00\x01\x01' * 5)

    def test_fromStringErrors(self):
        """
        keys.Key.fromString should raise BadKeyError when the key is invalid.
        """
        self.assertRaises(keys.BadKeyError, keys.Key.fromString, '')
        # no key data with a bad key type
        self.assertRaises(
            keys.BadKeyError, keys.Key.fromString, '', 'bad_type')
        # trying to decrypt a key which doesn't support encryption
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
            keydata.publicRSA_lsh, passphrase='unencrypted')
        # trying to decrypt a key with the wrong passphrase
        self.assertRaises(
            keys.EncryptedKeyError,
            keys.Key.fromString,
            keys.Key(self.rsaObj).toString('openssh', 'encrypted'))
        # key with no key data
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
            '-----BEGIN RSA KEY-----\nwA==\n')
        # key with invalid DEK Info
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
            """-----BEGIN ENCRYPTED RSA KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: weird type

4Ed/a9OgJWHJsne7yOGWeWMzHYKsxuP9w1v0aYcp+puS75wvhHLiUnNwxz0KDi6n
T3YkKLBsoCWS68ApR2J9yeQ6R+EyS+UQDrO9nwqo3DB5BT3Ggt8S1wE7vjNLQD0H
g/SJnlqwsECNhh8aAx+Ag0m3ZKOZiRD5mCkcDQsZET7URSmFytDKOjhFn3u6ZFVB
sXrfpYc6TJtOQlHd/52JB6aAbjt6afSv955Z7enIi+5yEJ5y7oYQTaE5zrFMP7N5
9LbfJFlKXxEddy/DErRLxEjmC+t4svHesoJKc2jjjyNPiOoGGF3kJXea62vsjdNV
gMK5Eged3TBVIk2dv8rtJUvyFeCUtjQ1UJZIebScRR47KrbsIpCmU8I4/uHWm5hW
0mOwvdx1L/mqx/BHqVU9Dw2COhOdLbFxlFI92chkovkmNk4P48ziyVnpm7ME22sE
vfCMsyirdqB1mrL4CSM7FXONv+CgfBfeYVkYW8RfJac9U1L/O+JNn7yee414O/rS
hRYw4UdWnH6Gg6niklVKWNY0ZwUZC8zgm2iqy8YCYuneS37jC+OEKP+/s6HSKuqk
2bzcl3/TcZXNSM815hnFRpz0anuyAsvwPNRyvxG2/DacJHL1f6luV4B0o6W410yf
qXQx01DLo7nuyhJqoH3UGCyyXB+/QUs0mbG2PAEn3f5dVs31JMdbt+PrxURXXjKk
4cexpUcIpqqlfpIRe3RD0sDVbH4OXsGhi2kiTfPZu7mgyFxKopRbn1KwU1qKinfY
EU9O4PoTak/tPT+5jFNhaP+HrURoi/pU8EAUNSktl7xAkHYwkN/9Cm7DeBghgf3n
8+tyCGYDsB5utPD0/Xe9yx0Qhc/kMm4xIyQDyA937dk3mUvLC9vulnAP8I+Izim0
fZ182+D1bWwykoD0997mUHG/AUChWR01V1OLwRyPv2wUtiS8VNG76Y2aqKlgqP1P
V+IvIEqR4ERvSBVFzXNF8Y6j/sVxo8+aZw+d0L1Ns/R55deErGg3B8i/2EqGd3r+
0jps9BqFHHWW87n3VyEB3jWCMj8Vi2EJIfa/7pSaViFIQn8LiBLf+zxG5LTOToK5
xkN42fReDcqi3UNfKNGnv4dsplyTR2hyx65lsj4bRKDGLKOuB1y7iB0AGb0LtcAI
dcsVlcCeUquDXtqKvRnwfIMg+ZunyjqHBhj3qgRgbXbT6zjaSdNnih569aTg0Vup
VykzZ7+n/KVcGLmvX0NesdoI7TKbq4TnEIOynuG5Sf+2GpARO5bjcWKSZeN/Ybgk
gccf8Cqf6XWqiwlWd0B7BR3SymeHIaSymC45wmbgdstrbk7Ppa2Tp9AZku8M2Y7c
8mY9b+onK075/ypiwBm4L4GRNTFLnoNQJXx0OSl4FNRWsn6ztbD+jZhu8Seu10Jw
SEJVJ+gmTKdRLYORJKyqhDet6g7kAxs4EoJ25WsOnX5nNr00rit+NkMPA7xbJT+7
CfI51GQLw7pUPeO2WNt6yZO/YkzZrqvTj5FEwybkUyBv7L0gkqu9wjfDdUw0fVHE
xEm4DxjEoaIp8dW/JOzXQ2EF+WaSOgdYsw3Ac+rnnjnNptCdOEDGP6QBkt+oXj4P
-----END RSA PRIVATE KEY-----""", passphrase='encrypted')
        # key with invalid encryption type
        self.assertRaises(
            keys.BadKeyError, keys.Key.fromString,
            """-----BEGIN ENCRYPTED RSA KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: FOO-123-BAR,01234567

4Ed/a9OgJWHJsne7yOGWeWMzHYKsxuP9w1v0aYcp+puS75wvhHLiUnNwxz0KDi6n
T3YkKLBsoCWS68ApR2J9yeQ6R+EyS+UQDrO9nwqo3DB5BT3Ggt8S1wE7vjNLQD0H
g/SJnlqwsECNhh8aAx+Ag0m3ZKOZiRD5mCkcDQsZET7URSmFytDKOjhFn3u6ZFVB
sXrfpYc6TJtOQlHd/52JB6aAbjt6afSv955Z7enIi+5yEJ5y7oYQTaE5zrFMP7N5
9LbfJFlKXxEddy/DErRLxEjmC+t4svHesoJKc2jjjyNPiOoGGF3kJXea62vsjdNV
gMK5Eged3TBVIk2dv8rtJUvyFeCUtjQ1UJZIebScRR47KrbsIpCmU8I4/uHWm5hW
0mOwvdx1L/mqx/BHqVU9Dw2COhOdLbFxlFI92chkovkmNk4P48ziyVnpm7ME22sE
vfCMsyirdqB1mrL4CSM7FXONv+CgfBfeYVkYW8RfJac9U1L/O+JNn7yee414O/rS
hRYw4UdWnH6Gg6niklVKWNY0ZwUZC8zgm2iqy8YCYuneS37jC+OEKP+/s6HSKuqk
2bzcl3/TcZXNSM815hnFRpz0anuyAsvwPNRyvxG2/DacJHL1f6luV4B0o6W410yf
qXQx01DLo7nuyhJqoH3UGCyyXB+/QUs0mbG2PAEn3f5dVs31JMdbt+PrxURXXjKk
4cexpUcIpqqlfpIRe3RD0sDVbH4OXsGhi2kiTfPZu7mgyFxKopRbn1KwU1qKinfY
EU9O4PoTak/tPT+5jFNhaP+HrURoi/pU8EAUNSktl7xAkHYwkN/9Cm7DeBghgf3n
8+tyCGYDsB5utPD0/Xe9yx0Qhc/kMm4xIyQDyA937dk3mUvLC9vulnAP8I+Izim0
fZ182+D1bWwykoD0997mUHG/AUChWR01V1OLwRyPv2wUtiS8VNG76Y2aqKlgqP1P
V+IvIEqR4ERvSBVFzXNF8Y6j/sVxo8+aZw+d0L1Ns/R55deErGg3B8i/2EqGd3r+
0jps9BqFHHWW87n3VyEB3jWCMj8Vi2EJIfa/7pSaViFIQn8LiBLf+zxG5LTOToK5
xkN42fReDcqi3UNfKNGnv4dsplyTR2hyx65lsj4bRKDGLKOuB1y7iB0AGb0LtcAI
dcsVlcCeUquDXtqKvRnwfIMg+ZunyjqHBhj3qgRgbXbT6zjaSdNnih569aTg0Vup
VykzZ7+n/KVcGLmvX0NesdoI7TKbq4TnEIOynuG5Sf+2GpARO5bjcWKSZeN/Ybgk
gccf8Cqf6XWqiwlWd0B7BR3SymeHIaSymC45wmbgdstrbk7Ppa2Tp9AZku8M2Y7c
8mY9b+onK075/ypiwBm4L4GRNTFLnoNQJXx0OSl4FNRWsn6ztbD+jZhu8Seu10Jw
SEJVJ+gmTKdRLYORJKyqhDet6g7kAxs4EoJ25WsOnX5nNr00rit+NkMPA7xbJT+7
CfI51GQLw7pUPeO2WNt6yZO/YkzZrqvTj5FEwybkUyBv7L0gkqu9wjfDdUw0fVHE
xEm4DxjEoaIp8dW/JOzXQ2EF+WaSOgdYsw3Ac+rnnjnNptCdOEDGP6QBkt+oXj4P
-----END RSA PRIVATE KEY-----""", passphrase='encrypted')
        # key with bad IV (AES)
        self.assertRaises(
            keys.BadKeyError, keys.Key.fromString,
            """-----BEGIN ENCRYPTED RSA KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,01234

4Ed/a9OgJWHJsne7yOGWeWMzHYKsxuP9w1v0aYcp+puS75wvhHLiUnNwxz0KDi6n
T3YkKLBsoCWS68ApR2J9yeQ6R+EyS+UQDrO9nwqo3DB5BT3Ggt8S1wE7vjNLQD0H
g/SJnlqwsECNhh8aAx+Ag0m3ZKOZiRD5mCkcDQsZET7URSmFytDKOjhFn3u6ZFVB
sXrfpYc6TJtOQlHd/52JB6aAbjt6afSv955Z7enIi+5yEJ5y7oYQTaE5zrFMP7N5
9LbfJFlKXxEddy/DErRLxEjmC+t4svHesoJKc2jjjyNPiOoGGF3kJXea62vsjdNV
gMK5Eged3TBVIk2dv8rtJUvyFeCUtjQ1UJZIebScRR47KrbsIpCmU8I4/uHWm5hW
0mOwvdx1L/mqx/BHqVU9Dw2COhOdLbFxlFI92chkovkmNk4P48ziyVnpm7ME22sE
vfCMsyirdqB1mrL4CSM7FXONv+CgfBfeYVkYW8RfJac9U1L/O+JNn7yee414O/rS
hRYw4UdWnH6Gg6niklVKWNY0ZwUZC8zgm2iqy8YCYuneS37jC+OEKP+/s6HSKuqk
2bzcl3/TcZXNSM815hnFRpz0anuyAsvwPNRyvxG2/DacJHL1f6luV4B0o6W410yf
qXQx01DLo7nuyhJqoH3UGCyyXB+/QUs0mbG2PAEn3f5dVs31JMdbt+PrxURXXjKk
4cexpUcIpqqlfpIRe3RD0sDVbH4OXsGhi2kiTfPZu7mgyFxKopRbn1KwU1qKinfY
EU9O4PoTak/tPT+5jFNhaP+HrURoi/pU8EAUNSktl7xAkHYwkN/9Cm7DeBghgf3n
8+tyCGYDsB5utPD0/Xe9yx0Qhc/kMm4xIyQDyA937dk3mUvLC9vulnAP8I+Izim0
fZ182+D1bWwykoD0997mUHG/AUChWR01V1OLwRyPv2wUtiS8VNG76Y2aqKlgqP1P
V+IvIEqR4ERvSBVFzXNF8Y6j/sVxo8+aZw+d0L1Ns/R55deErGg3B8i/2EqGd3r+
0jps9BqFHHWW87n3VyEB3jWCMj8Vi2EJIfa/7pSaViFIQn8LiBLf+zxG5LTOToK5
xkN42fReDcqi3UNfKNGnv4dsplyTR2hyx65lsj4bRKDGLKOuB1y7iB0AGb0LtcAI
dcsVlcCeUquDXtqKvRnwfIMg+ZunyjqHBhj3qgRgbXbT6zjaSdNnih569aTg0Vup
VykzZ7+n/KVcGLmvX0NesdoI7TKbq4TnEIOynuG5Sf+2GpARO5bjcWKSZeN/Ybgk
gccf8Cqf6XWqiwlWd0B7BR3SymeHIaSymC45wmbgdstrbk7Ppa2Tp9AZku8M2Y7c
8mY9b+onK075/ypiwBm4L4GRNTFLnoNQJXx0OSl4FNRWsn6ztbD+jZhu8Seu10Jw
SEJVJ+gmTKdRLYORJKyqhDet6g7kAxs4EoJ25WsOnX5nNr00rit+NkMPA7xbJT+7
CfI51GQLw7pUPeO2WNt6yZO/YkzZrqvTj5FEwybkUyBv7L0gkqu9wjfDdUw0fVHE
xEm4DxjEoaIp8dW/JOzXQ2EF+WaSOgdYsw3Ac+rnnjnNptCdOEDGP6QBkt+oXj4P
-----END RSA PRIVATE KEY-----""", passphrase='encrypted')
        # key with bad IV (DES3)
        self.assertRaises(
            keys.BadKeyError, keys.Key.fromString,
            """-----BEGIN ENCRYPTED RSA KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,01234

4Ed/a9OgJWHJsne7yOGWeWMzHYKsxuP9w1v0aYcp+puS75wvhHLiUnNwxz0KDi6n
T3YkKLBsoCWS68ApR2J9yeQ6R+EyS+UQDrO9nwqo3DB5BT3Ggt8S1wE7vjNLQD0H
g/SJnlqwsECNhh8aAx+Ag0m3ZKOZiRD5mCkcDQsZET7URSmFytDKOjhFn3u6ZFVB
sXrfpYc6TJtOQlHd/52JB6aAbjt6afSv955Z7enIi+5yEJ5y7oYQTaE5zrFMP7N5
9LbfJFlKXxEddy/DErRLxEjmC+t4svHesoJKc2jjjyNPiOoGGF3kJXea62vsjdNV
gMK5Eged3TBVIk2dv8rtJUvyFeCUtjQ1UJZIebScRR47KrbsIpCmU8I4/uHWm5hW
0mOwvdx1L/mqx/BHqVU9Dw2COhOdLbFxlFI92chkovkmNk4P48ziyVnpm7ME22sE
vfCMsyirdqB1mrL4CSM7FXONv+CgfBfeYVkYW8RfJac9U1L/O+JNn7yee414O/rS
hRYw4UdWnH6Gg6niklVKWNY0ZwUZC8zgm2iqy8YCYuneS37jC+OEKP+/s6HSKuqk
2bzcl3/TcZXNSM815hnFRpz0anuyAsvwPNRyvxG2/DacJHL1f6luV4B0o6W410yf
qXQx01DLo7nuyhJqoH3UGCyyXB+/QUs0mbG2PAEn3f5dVs31JMdbt+PrxURXXjKk
4cexpUcIpqqlfpIRe3RD0sDVbH4OXsGhi2kiTfPZu7mgyFxKopRbn1KwU1qKinfY
EU9O4PoTak/tPT+5jFNhaP+HrURoi/pU8EAUNSktl7xAkHYwkN/9Cm7DeBghgf3n
8+tyCGYDsB5utPD0/Xe9yx0Qhc/kMm4xIyQDyA937dk3mUvLC9vulnAP8I+Izim0
fZ182+D1bWwykoD0997mUHG/AUChWR01V1OLwRyPv2wUtiS8VNG76Y2aqKlgqP1P
V+IvIEqR4ERvSBVFzXNF8Y6j/sVxo8+aZw+d0L1Ns/R55deErGg3B8i/2EqGd3r+
0jps9BqFHHWW87n3VyEB3jWCMj8Vi2EJIfa/7pSaViFIQn8LiBLf+zxG5LTOToK5
xkN42fReDcqi3UNfKNGnv4dsplyTR2hyx65lsj4bRKDGLKOuB1y7iB0AGb0LtcAI
dcsVlcCeUquDXtqKvRnwfIMg+ZunyjqHBhj3qgRgbXbT6zjaSdNnih569aTg0Vup
VykzZ7+n/KVcGLmvX0NesdoI7TKbq4TnEIOynuG5Sf+2GpARO5bjcWKSZeN/Ybgk
gccf8Cqf6XWqiwlWd0B7BR3SymeHIaSymC45wmbgdstrbk7Ppa2Tp9AZku8M2Y7c
8mY9b+onK075/ypiwBm4L4GRNTFLnoNQJXx0OSl4FNRWsn6ztbD+jZhu8Seu10Jw
SEJVJ+gmTKdRLYORJKyqhDet6g7kAxs4EoJ25WsOnX5nNr00rit+NkMPA7xbJT+7
CfI51GQLw7pUPeO2WNt6yZO/YkzZrqvTj5FEwybkUyBv7L0gkqu9wjfDdUw0fVHE
xEm4DxjEoaIp8dW/JOzXQ2EF+WaSOgdYsw3Ac+rnnjnNptCdOEDGP6QBkt+oXj4P
-----END RSA PRIVATE KEY-----""", passphrase='encrypted')

    def test_fromFile(self):
        """
        Test that fromFile works correctly.
        """
        key_path, _ = self.tempFile(
            content=keydata.privateRSA_openssh)

        self.assertEqual(
            keys.Key.fromFile(key_path),
            keys.Key.fromString(keydata.privateRSA_openssh))

        self.assertRaises(
            keys.BadKeyError, keys.Key.fromFile, key_path, 'bad_type')

        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromFile, key_path, passphrase='unencrypted')

    def test_init(self):
        """
        Test that the PublicKey object is initialized correctly.
        """
        obj = keys.Key._fromRSAComponents(n=long(5), e=long(3))._keyObject
        key = keys.Key(obj)
        self.assertEqual(key._keyObject, obj)

    def test_equal(self):
        """
        Test that Key objects are compared correctly.
        """
        rsa1 = keys.Key(self.rsaObj)
        rsa2 = keys.Key(self.rsaObj)
        rsa3 = keys.Key(
            keys.Key._fromRSAComponents(n=long(5), e=long(3))._keyObject)
        dsa = keys.Key(self.dsaObj)
        self.assertTrue(rsa1 == rsa2)
        self.assertFalse(rsa1 == rsa3)
        self.assertFalse(rsa1 == dsa)
        self.assertFalse(rsa1 == object)
        self.assertFalse(rsa1 is None)

    def test_notEqual(self):
        """
        Test that Key objects are not-compared correctly.
        """
        rsa1 = keys.Key(self.rsaObj)
        rsa2 = keys.Key(self.rsaObj)
        rsa3 = keys.Key(
            keys.Key._fromRSAComponents(n=long(5), e=long(3))._keyObject)
        dsa = keys.Key(self.dsaObj)
        self.assertFalse(rsa1 != rsa2)
        self.assertTrue(rsa1 != rsa3)
        self.assertTrue(rsa1 != dsa)
        self.assertTrue(rsa1 != object)
        self.assertTrue(rsa1 is not None)

    def test_dataError(self):
        """
        The L{keys.Key.data} method raises RuntimeError for bad keys.
        """
        badKey = keys.Key(b'')
        self.assertRaises(RuntimeError, badKey.data)

    def test_fingerprintdefault(self):
        """
        Test that the fingerprint method returns fingerprint in
        L{FingerprintFormats.MD5-HEX} format by default.
        """
        self.assertEqual(keys.Key(self.rsaObj).fingerprint(),
            '85:25:04:32:58:55:96:9f:57:ee:fb:a8:1a:ea:69:da')
        self.assertEqual(keys.Key(self.dsaObj).fingerprint(),
            '63:15:b3:0e:e6:4f:50:de:91:48:3d:01:6b:b3:13:c1')

    def test_fingerprint_md5_hex(self):
        """
        fingerprint method generates key fingerprint in
        L{FingerprintFormats.MD5-HEX} format if explicitly specified.
        """
        self.assertEqual(
            keys.Key(self.rsaObj).fingerprint(
                keys.FingerprintFormats.MD5_HEX),
            '85:25:04:32:58:55:96:9f:57:ee:fb:a8:1a:ea:69:da')
        self.assertEqual(
            keys.Key(self.dsaObj).fingerprint(
                keys.FingerprintFormats.MD5_HEX),
            '63:15:b3:0e:e6:4f:50:de:91:48:3d:01:6b:b3:13:c1')

    def test_fingerprintsha256(self):
        """
        fingerprint method generates key fingerprint in
        L{FingerprintFormats.SHA256-BASE64} format if explicitly specified.
        """
        self.assertEqual(
            keys.Key(self.rsaObj).fingerprint(
                keys.FingerprintFormats.SHA256_BASE64),
            'FBTCOoknq0mHy+kpfnY9tDdcAJuWtCpuQMaV3EsvbUI=')
        self.assertEqual(
            keys.Key(self.dsaObj).fingerprint(
                keys.FingerprintFormats.SHA256_BASE64),
            'Wz5o2YbKyxOEcJn1au/UaALSVruUzfz0vaLI1xiIGyY=')

    def test_fingerprintsha1(self):
        """
        fingerprint method generates key fingerprint in
        L{FingerprintFormats.SHA1-BASE64} format if explicitly specified.
        """
        self.assertEqual(
            keys.Key(self.rsaObj).fingerprint(
                keys.FingerprintFormats.SHA1_BASE64),
            'tuUFlgv3kknie9WYExgS7OQj54k=')
        self.assertEqual(
            keys.Key(self.dsaObj).fingerprint(
                keys.FingerprintFormats.SHA1_BASE64),
            '9CCuTybG5aORtuW4jrFcp0PbK4U=')

    def test_fingerprintBadFormat(self):
        """
        A C{BadFingerPrintFormat} error is raised when unsupported
        formats are requested.
        """
        with self.assertRaises(keys.BadFingerPrintFormat) as em:
            keys.Key(self.rsaObj).fingerprint('sha256-base')
        self.assertEqual(
            'Unsupported fingerprint format: sha256-base',
            em.exception.args[0])

    def test_type(self):
        """
        Test that the type method returns the correct type for an object.
        """
        self.assertEqual(keys.Key(self.rsaObj).type(), 'RSA')
        self.assertEqual(keys.Key(self.rsaObj).sshType(), b'ssh-rsa')
        self.assertEqual(keys.Key(self.dsaObj).type(), 'DSA')
        self.assertEqual(keys.Key(self.dsaObj).sshType(), b'ssh-dss')
        self.assertEqual(keys.Key(self.ecObj).type(), 'EC')
        self.assertEqual(keys.Key(self.ecObj).sshType(),
                        keydata.ECDatanistp256['curve'])
        self.assertRaises(RuntimeError, keys.Key(None).type)
        self.assertRaises(RuntimeError, keys.Key(None).sshType)
        self.assertRaises(RuntimeError, keys.Key(self).type)
        self.assertRaises(RuntimeError, keys.Key(self).sshType)

    def test_fromBlobUnsupportedType(self):
        """
        A C{BadKeyError} error is raised whey the blob has an unsupported
        key type.
        """
        badBlob = common.NS(b'ssh-bad')

        self.assertRaises(keys.BadKeyError,
                keys.Key.fromString, badBlob)

    def test_fromBlobRSA(self):
        """
        A public RSA key is correctly generated from a public key blob.
        """
        rsaPublicData = {
            'n': keydata.RSAData['n'],
            'e': keydata.RSAData['e'],
            }
        rsaBlob = (
            common.NS(b'ssh-rsa') +
            common.MP(rsaPublicData['e']) +
            common.MP(rsaPublicData['n'])
            )

        rsaKey = keys.Key.fromString(rsaBlob)

        self.assertTrue(rsaKey.isPublic())
        self.assertEqual(rsaPublicData, rsaKey.data())

    def test_fromBlobDSA(self):
        """
        A public DSA key is correctly generated from a public key blob.
        """
        dsaPublicData = {
            'p': keydata.DSAData['p'],
            'q': keydata.DSAData['q'],
            'g': keydata.DSAData['g'],
            'y': keydata.DSAData['y'],
            }
        dsaBlob = (
            common.NS(b'ssh-dss') +
            common.MP(dsaPublicData['p']) +
            common.MP(dsaPublicData['q']) +
            common.MP(dsaPublicData['g']) +
            common.MP(dsaPublicData['y'])
            )

        dsaKey = keys.Key.fromString(dsaBlob)

        self.assertTrue(dsaKey.isPublic())
        self.assertEqual(dsaPublicData, dsaKey.data())

    def test_fromBlobECDSA(self):
        """
        Key.fromString generates ECDSA keys from blobs.
        """
        from cryptography import utils

        ecPublicData = {
            'x': keydata.ECDatanistp256['x'],
            'y': keydata.ECDatanistp256['y'],
            'curve': keydata.ECDatanistp256['curve']
            }

        ecblob = (common.NS(ecPublicData['curve']) +
                  common.NS(ecPublicData['curve'][-8:]) +
                  common.NS(b'\x04' +
                    utils.int_to_bytes(ecPublicData['x'], 32) +
                    utils.int_to_bytes(ecPublicData['y'], 32))
            )

        eckey = keys.Key.fromString(ecblob)
        self.assertTrue(eckey.isPublic())
        self.assertEqual(ecPublicData, eckey.data())

    def test_fromPrivateBlobUnsupportedType(self):
        """
        C{BadKeyError} is raised when loading a private blob with an
        unsupported type.
        """
        badBlob = common.NS(b'ssh-bad')

        self.assertRaises(
            keys.BadKeyError, keys.Key._fromString_PRIVATE_BLOB, badBlob)

    def test_fromPrivateBlobRSA(self):
        """
        A private RSA key is correctly generated from a private key blob.
        """
        rsaBlob = (
            common.NS(b'ssh-rsa') +
            common.MP(keydata.RSAData['n']) +
            common.MP(keydata.RSAData['e']) +
            common.MP(keydata.RSAData['d']) +
            common.MP(keydata.RSAData['u']) +
            common.MP(keydata.RSAData['p']) +
            common.MP(keydata.RSAData['q'])
            )

        rsaKey = keys.Key._fromString_PRIVATE_BLOB(rsaBlob)

        self.assertFalse(rsaKey.isPublic())
        self.assertEqual(keydata.RSAData, rsaKey.data())

    def test_fromPrivateBlobDSA(self):
        """
        A private DSA key is correctly generated from a private key blob.
        """
        dsaBlob = (
            common.NS(b'ssh-dss') +
            common.MP(keydata.DSAData['p']) +
            common.MP(keydata.DSAData['q']) +
            common.MP(keydata.DSAData['g']) +
            common.MP(keydata.DSAData['y']) +
            common.MP(keydata.DSAData['x'])
            )

        dsaKey = keys.Key._fromString_PRIVATE_BLOB(dsaBlob)

        self.assertFalse(dsaKey.isPublic())
        self.assertEqual(keydata.DSAData, dsaKey.data())

    def test_fromPrivateBlobECDSA(self):
        """
        A private EC key is correctly generated from a private key blob.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        publicNumbers = ec.EllipticCurvePublicNumbers(
            x=keydata.ECDatanistp256['x'], y=keydata.ECDatanistp256['y'],
            curve=ec.SECP256R1())
        ecblob = (
            common.NS(keydata.ECDatanistp256['curve']) +
            common.NS(keydata.ECDatanistp256['curve'][-8:]) +
            common.NS(publicNumbers.public_key(default_backend()).public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            )) +
            common.MP(keydata.ECDatanistp256['privateValue'])
        )

        eckey = keys.Key._fromString_PRIVATE_BLOB(ecblob)

        self.assertFalse(eckey.isPublic())
        self.assertEqual(keydata.ECDatanistp256, eckey.data())

    def test_blobRSA(self):
        """
        Return the over-the-wire SSH format of the RSA public key.
        """
        self.assertEqual(
            keys.Key(self.rsaObj).blob(),
            common.NS(b'ssh-rsa') +
            common.MP(self.rsaObj.private_numbers().public_numbers.e) +
            common.MP(self.rsaObj.private_numbers().public_numbers.n)
            )

    def test_blobDSA(self):
        """
        Return the over-the-wire SSH format of the DSA public key.
        """
        publicNumbers = self.dsaObj.private_numbers().public_numbers

        self.assertEqual(
            keys.Key(self.dsaObj).blob(),
            common.NS(b'ssh-dss') +
            common.MP(publicNumbers.parameter_numbers.p) +
            common.MP(publicNumbers.parameter_numbers.q) +
            common.MP(publicNumbers.parameter_numbers.g) +
            common.MP(publicNumbers.y)
            )

    def test_blobEC(self):
        """
        Return the over-the-wire SSH format of the EC public key.
        """
        from cryptography import utils

        byteLength = (self.ecObj.curve.key_size + 7) // 8
        self.assertEqual(
            keys.Key(self.ecObj).blob(),
            common.NS(keydata.ECDatanistp256['curve']) +
            common.NS(keydata.ECDatanistp256['curve'][-8:]) +
            common.NS(b'\x04' +
               utils.int_to_bytes(
                 self.ecObj.private_numbers().public_numbers.x, byteLength) +
                   utils.int_to_bytes(
                   self.ecObj.private_numbers().public_numbers.y, byteLength))
            )

    def test_blobNoKey(self):
        """
        C{RuntimeError} is raised when the blob is requested for a Key
        which is not wrapping anything.
        """
        badKey = keys.Key(None)

        self.assertRaises(RuntimeError, badKey.blob)

    def test_privateBlobRSA(self):
        """
        L{keys.Key.privateBlob} returns the SSH protocol-level format of an
        RSA private key.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        numbers = self.rsaObj.private_numbers()
        u = rsa.rsa_crt_iqmp(numbers.q, numbers.p)
        self.assertEqual(
            keys.Key(self.rsaObj).privateBlob(),
            common.NS(b'ssh-rsa') +
            common.MP(self.rsaObj.private_numbers().public_numbers.n) +
            common.MP(self.rsaObj.private_numbers().public_numbers.e) +
            common.MP(self.rsaObj.private_numbers().d) +
            common.MP(u) +
            common.MP(self.rsaObj.private_numbers().p) +
            common.MP(self.rsaObj.private_numbers().q)
            )

    def test_privateBlobDSA(self):
        """
        L{keys.Key.privateBlob} returns the SSH protocol-level format of a DSA
        private key.
        """
        publicNumbers = self.dsaObj.private_numbers().public_numbers

        self.assertEqual(
            keys.Key(self.dsaObj).privateBlob(),
            common.NS(b'ssh-dss') +
            common.MP(publicNumbers.parameter_numbers.p) +
            common.MP(publicNumbers.parameter_numbers.q) +
            common.MP(publicNumbers.parameter_numbers.g) +
            common.MP(publicNumbers.y) +
            common.MP(self.dsaObj.private_numbers().x)
            )

    def test_privateBlobEC(self):
        """
        L{keys.Key.privateBlob} returns the SSH ptotocol-level format of EC
        private key.
        """
        self.assertEqual(
            keys.Key(self.ecObj).privateBlob(),
            common.NS(keydata.ECDatanistp256['curve']) +
            common.MP(self.ecObj.private_numbers().public_numbers.x) +
            common.MP(self.ecObj.private_numbers().public_numbers.y) +
            common.MP(self.ecObj.private_numbers().private_value)
            )

    def test_privateBlobNoKeyObject(self):
        """
        Raises L{RuntimeError} if the underlying key object does not exists.
        """
        badKey = keys.Key(None)

        self.assertRaises(RuntimeError, badKey.privateBlob)

    def test_toOpenSSHRSA(self):
        """
        L{keys.Key.toString} serializes an RSA key in OpenSSH format.
        """
        key = keys.Key.fromString(keydata.privateRSA_agentv3)
        self.assertEqual(key.toString('openssh'), keydata.privateRSA_openssh)
        self.assertEqual(key.toString('openssh', b'encrypted'),
                keydata.privateRSA_openssh_encrypted)
        self.assertEqual(key.public().toString('openssh'),
                keydata.publicRSA_openssh[:-8])
        self.assertEqual(key.public().toString('openssh', b'comment'),
                keydata.publicRSA_openssh)

    def test_toOpenSSHDSA(self):
        """
        L{keys.Key.toString} serializes a DSA key in OpenSSH format.
        """
        key = keys.Key.fromString(keydata.privateDSA_lsh)
        self.assertEqual(key.toString('openssh'), keydata.privateDSA_openssh)
        self.assertEqual(key.public().toString('openssh', b'comment'),
                keydata.publicDSA_openssh)
        self.assertEqual(key.public().toString('openssh'),
                keydata.publicDSA_openssh[:-8])

    def test_toOpenSSHECDSA(self):
        """
        L{keys.Key.toString} serializes a ECDSA key in OpenSSH format.
        """
        key = keys.Key.fromString(keydata.privateECDSA_openssh)
        self.assertEqual(key.public().toString('openssh', b'comment'),
                keydata.publicECDSA_openssh)
        self.assertEqual(key.public().toString('openssh'),
                keydata.publicECDSA_openssh[:-8])

    def test_toLSHRSA(self):
        """
        L{keys.Key.toString} serializes an RSA key in LSH format.
        """
        key = keys.Key.fromString(keydata.privateRSA_openssh)
        self.assertEqual(key.toString('lsh'), keydata.privateRSA_lsh)
        self.assertEqual(key.public().toString('lsh'),
                keydata.publicRSA_lsh)

    def test_toLSHDSA(self):
        """
        L{keys.Key.toString} serializes a DSA key in LSH format.
        """
        key = keys.Key.fromString(keydata.privateDSA_openssh)
        self.assertEqual(key.toString('lsh'), keydata.privateDSA_lsh)
        self.assertEqual(key.public().toString('lsh'),
                keydata.publicDSA_lsh)

    def test_toAgentv3RSA(self):
        """
        L{keys.Key.toString} serializes an RSA key in Agent v3 format.
        """
        key = keys.Key.fromString(keydata.privateRSA_openssh)
        self.assertEqual(key.toString('agentv3'), keydata.privateRSA_agentv3)

    def test_toAgentv3DSA(self):
        """
        L{keys.Key.toString} serializes a DSA key in Agent v3 format.
        """
        key = keys.Key.fromString(keydata.privateDSA_openssh)
        self.assertEqual(key.toString('agentv3'), keydata.privateDSA_agentv3)

    def test_toStringErrors(self):
        """
        L{keys.Key.toString} raises L{keys.BadKeyError} when passed an invalid
        format type.
        """
        self.assertRaises(keys.BadKeyError, keys.Key(self.rsaObj).toString,
                'bad_type')

    def test_signAndVerifyRSA(self):
        """
        Signed data can be verified using RSA.
        """
        data = b'some-data'
        key = keys.Key.fromString(keydata.privateRSA_openssh)
        signature = key.sign(data)
        self.assertTrue(key.public().verify(signature, data))
        self.assertTrue(key.verify(signature, data))

    def test_signAndVerifyDSA(self):
        """
        Signed data can be verified using DSA.
        """
        data = b'some-data'
        key = keys.Key.fromString(keydata.privateDSA_openssh)
        signature = key.sign(data)
        self.assertTrue(key.public().verify(signature, data))
        self.assertTrue(key.verify(signature, data))

    def test_signAndVerifyEC(self):
        """
        Signed data can be verified using EC.
        """
        data = b'some-data'
        key = keys.Key.fromString(keydata.privateECDSA_openssh)
        signature = key.sign(data)

        key384 = keys.Key.fromString(keydata.privateECDSA_openssh384)
        signature384 = key384.sign(data)

        key521 = keys.Key.fromString(keydata.privateECDSA_openssh521)
        signature521 = key521.sign(data)

        self.assertTrue(key.public().verify(signature, data))
        self.assertTrue(key.verify(signature, data))
        self.assertTrue(key384.public().verify(signature384, data))
        self.assertTrue(key384.verify(signature384, data))
        self.assertTrue(key521.public().verify(signature521, data))
        self.assertTrue(key521.verify(signature521, data))

    def test_verifyRSA(self):
        """
        A known-good RSA signature verifies successfully.
        """
        key = keys.Key.fromString(keydata.publicRSA_openssh)
        self.assertTrue(key.verify(self.rsaSignature, b''))
        self.assertFalse(key.verify(self.rsaSignature, b'a'))
        self.assertFalse(key.verify(self.dsaSignature, b''))

    def test_verifyDSA(self):
        """
        A known-good DSA signature verifies successfully.
        """
        key = keys.Key.fromString(keydata.publicDSA_openssh)
        self.assertTrue(key.verify(self.dsaSignature, b''))
        self.assertFalse(key.verify(self.dsaSignature, b'a'))
        self.assertFalse(key.verify(self.rsaSignature, b''))

    def test_verifyDSANoPrefix(self):
        """
        Some commercial SSH servers send DSA keys as 2 20-byte numbers;
        they are still verified as valid keys.
        """
        key = keys.Key.fromString(keydata.publicDSA_openssh)
        self.assertTrue(key.verify(self.dsaSignature[-40:], b''))

    def test_reprPrivateRSA(self):
        """
        The repr of a L{keys.Key} contains all of the RSA components for an RSA
        private key.
        """
        self.assertEqual(repr(keys.Key(self.rsaObj)),
"""<RSA Private Key (2048 bits)
attr d:
\t21:4c:08:66:a2:28:d5:b4:fb:8e:0f:72:1b:85:09:
\t00:b9:f2:4e:37:f0:1c:57:4b:e3:51:7f:9e:23:a7:
\te4:3a:98:55:1b:ea:8b:7a:98:1e:bc:d8:ba:b1:f9:
\t89:12:18:60:ac:e8:cc:0b:4e:09:5a:40:6a:ba:2f:
\t99:f8:b3:24:60:84:b9:ce:69:95:9a:f9:e2:fc:1f:
\t51:4d:27:15:db:2b:27:ad:ef:b4:69:ac:be:7d:10:
\teb:86:47:70:73:b4:00:87:95:15:3b:37:f9:e7:14:
\te7:80:bb:68:1e:1b:e6:dd:bb:73:63:b9:67:e6:b2:
\t27:7f:cf:cf:30:9b:c2:98:fd:d9:18:36:2f:36:2e:
\tf1:3d:81:7a:9f:e1:03:2d:47:db:34:51:62:39:dd:
\t4f:e9:ac:a8:8b:d9:d6:f3:84:c4:17:b9:71:9d:06:
\t08:42:78:4d:bb:c5:2a:f4:c3:58:cd:55:2b:ed:be:
\t33:5f:04:ea:7b:e6:04:24:63:f2:2d:d7:3d:1b:6c:
\td5:9c:63:43:2f:92:88:8d:3e:6e:da:18:37:d8:0f:
\t25:67:89:1d:b9:46:34:5e:c9:ce:c4:8b:ed:92:5a:
\t33:07:0f:df:86:08:f9:92:e9:db:eb:38:08:36:c9:
\tcd:cd:0a:01:48:5b:39:3e:7a:ca:c6:80:a9:dc:d4:
\t39
attr e:
\t01:00:01
attr n:
\t00:d5:6a:ac:78:23:d6:d6:1b:ec:25:a1:50:c4:77:
\t63:50:84:45:01:55:42:14:2a:2a:e0:d0:60:ee:d4:
\te9:a3:ad:4a:fa:39:06:5e:84:55:75:5f:00:36:bf:
\t6f:aa:2a:3f:83:26:37:c1:69:2e:5b:fd:f0:f3:d2:
\t7d:d6:98:cd:3a:40:78:d5:ca:a8:18:c0:11:93:24:
\t09:0c:81:4c:8f:f7:9c:ed:13:16:6a:a4:04:e9:49:
\t77:c3:e4:55:64:b3:79:68:9e:2c:08:eb:ac:e8:04:
\t2d:21:77:05:a7:8e:ef:53:30:0d:a5:e5:bb:3d:6a:
\te2:09:36:6f:fd:34:d3:7d:6f:46:ff:87:da:a9:29:
\t27:aa:ff:ad:f5:85:e6:3e:1a:b8:7a:1d:4a:b1:ea:
\tc0:5a:f7:30:df:1f:c2:a4:e4:ef:3f:91:49:96:40:
\td5:19:77:2d:37:c3:5e:ec:9d:a6:3a:44:a5:c2:a4:
\t29:dd:d5:ba:9c:3d:45:b3:c6:2c:18:64:d5:ba:3d:
\tdf:ab:7f:cd:42:ac:a7:f1:18:0b:a0:58:15:62:0b:
\ta4:2a:6e:43:c3:e4:04:9f:35:a3:47:8e:46:ed:33:
\ta5:65:bd:bc:3b:29:6e:02:0b:57:df:74:e8:13:b4:
\t37:35:7e:83:5f:20:26:60:a6:dc:ad:8b:c6:6c:79:
\t98:f7
attr p:
\t00:d9:70:06:d8:e2:bc:d4:78:91:50:94:d4:c1:1b:
\t89:38:6c:46:64:5a:51:a0:9a:07:3d:48:8f:03:51:
\tcc:6b:12:8e:7d:1a:b1:65:e7:71:75:39:e0:32:05:
\t75:8d:18:4c:af:93:b1:49:b1:66:5f:78:62:7a:d1:
\t0c:ca:e6:4d:43:b3:9c:f4:6b:7d:e6:0c:98:dc:cf:
\t21:62:8e:d5:2e:12:de:04:ae:d7:24:6e:83:31:a2:
\t15:a2:44:3d:22:a9:62:26:22:b9:b2:ed:54:0a:9d:
\t08:83:a7:07:0d:ff:19:18:8e:d8:ab:1d:da:48:9c:
\t31:68:11:a1:66:6d:e3:d8:1d
attr q:
\t00:fb:44:17:8b:a4:36:be:1e:37:1d:a7:f6:61:6c:
\t04:c4:aa:dd:78:3e:07:8c:1e:33:02:ae:03:14:87:
\t83:7a:e5:9e:7d:08:67:a8:f2:aa:bf:12:70:cf:72:
\ta9:a7:c7:0b:1d:88:d5:20:fd:9c:63:ca:47:30:55:
\t4e:8b:c4:cf:f4:7f:16:a4:92:12:74:a1:09:c2:c4:
\t6e:9c:8c:33:ef:a5:e5:f7:e0:2b:ad:4f:5c:11:aa:
\t1a:84:37:5b:fd:7a:ea:c3:cd:7c:b0:c8:e4:1f:54:
\t63:b5:c7:af:df:f4:09:a7:fc:c7:25:fc:5c:e9:91:
\td7:92:c5:98:1e:56:d3:b1:23
attr u:
\t00:85:4b:1b:7a:9b:12:10:37:9e:1f:ad:5e:da:fe:
\tc6:96:fe:df:35:6b:b9:34:e2:16:97:92:26:09:bd:
\tbd:70:20:03:a7:35:bd:2d:1b:a0:d2:07:47:2b:d4:
\tde:a8:a8:07:07:1b:b8:04:20:a7:27:41:3c:6c:39:
\t39:e9:41:ce:e7:17:1d:d1:4c:5c:bc:3d:d2:26:26:
\tfe:6a:d6:fd:48:72:ae:46:fa:7b:c3:d3:19:60:44:
\t1d:a5:13:a7:80:f5:63:29:d4:7a:5d:06:07:16:5d:
\tf6:8b:3d:cb:64:3a:e2:84:5a:4d:8c:06:2d:2d:9d:
\t1c:eb:83:4c:78:3d:79:54:ce>""")

    def test_reprPublicRSA(self):
        """
        The repr of a L{keys.Key} contains all of the RSA components for an RSA
        public key.
        """
        self.assertEqual(repr(keys.Key(self.rsaObj).public()),
"""<RSA Public Key (2048 bits)
attr e:
\t01:00:01
attr n:
\t00:d5:6a:ac:78:23:d6:d6:1b:ec:25:a1:50:c4:77:
\t63:50:84:45:01:55:42:14:2a:2a:e0:d0:60:ee:d4:
\te9:a3:ad:4a:fa:39:06:5e:84:55:75:5f:00:36:bf:
\t6f:aa:2a:3f:83:26:37:c1:69:2e:5b:fd:f0:f3:d2:
\t7d:d6:98:cd:3a:40:78:d5:ca:a8:18:c0:11:93:24:
\t09:0c:81:4c:8f:f7:9c:ed:13:16:6a:a4:04:e9:49:
\t77:c3:e4:55:64:b3:79:68:9e:2c:08:eb:ac:e8:04:
\t2d:21:77:05:a7:8e:ef:53:30:0d:a5:e5:bb:3d:6a:
\te2:09:36:6f:fd:34:d3:7d:6f:46:ff:87:da:a9:29:
\t27:aa:ff:ad:f5:85:e6:3e:1a:b8:7a:1d:4a:b1:ea:
\tc0:5a:f7:30:df:1f:c2:a4:e4:ef:3f:91:49:96:40:
\td5:19:77:2d:37:c3:5e:ec:9d:a6:3a:44:a5:c2:a4:
\t29:dd:d5:ba:9c:3d:45:b3:c6:2c:18:64:d5:ba:3d:
\tdf:ab:7f:cd:42:ac:a7:f1:18:0b:a0:58:15:62:0b:
\ta4:2a:6e:43:c3:e4:04:9f:35:a3:47:8e:46:ed:33:
\ta5:65:bd:bc:3b:29:6e:02:0b:57:df:74:e8:13:b4:
\t37:35:7e:83:5f:20:26:60:a6:dc:ad:8b:c6:6c:79:
\t98:f7>""")

    def test_reprPublicECDSA(self):
        """
        The repr of a L{keys.Key} contains all the OpenSSH format for an ECDSA
        public key.
        """
        self.assertEqual(repr(keys.Key(self.ecObj).public()),
"""<Elliptic Curve Public Key (256 bits)
curve:
\tecdsa-sha2-nistp256
x:
\t76282513020392096317118503144964731774299773481750550543382904345687059013883
y:""" +
"\n\t8154319786460285263226566476944164753434437589431431968106113715931064" +
"6683104>\n")

    def test_reprPrivateECDSA(self):
        """
        The repr of a L{keys.Key} contains all the OpenSSH format for an ECDSA
        private key.
        """
        self.assertEqual(repr(keys.Key(self.ecObj)),
"""<Elliptic Curve Private Key (256 bits)
curve:
\tecdsa-sha2-nistp256
privateValue:
\t34638743477210341700964008455655698253555655678826059678074967909361042656500
x:
\t76282513020392096317118503144964731774299773481750550543382904345687059013883
y:""" +
"\n\t8154319786460285263226566476944164753434437589431431968106113715931064" +
"6683104>\n")

################################################################
# Extra tests
#
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
        self.assertEqual(1024, sut.size())
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
        self.assertEqual(1024, sut.size())
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
        self.assertEqual(1024, sut.size())
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
        self.assertEqual(1024, sut.size())
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
            data['q'])
        self.assertEqual(long(
            '12151328104249520956550929707892880056509323657595783040548358917'
            '98785549316902458371621691657702435263762556929800891556172971312'
            '6473919204485168003686593L'),
            data['p'])
        self.assertEqual(long(
            '48025268260110814473325498559726067155427614012608550802573547885'
            '48894562354231797601376827466469492368471033644629931755771678685'
            '474342157953188378164913L'),
            data['u'])

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

    def test_fromString_BLOB(self):
        """
        Test that a public key is correctly generated from a public key blob.
        """
        rsaBlob = common.NS('ssh-rsa') + common.MP(3) + common.MP(7)
        rsaKey = keys.Key.fromString(rsaBlob)
        p = long("10292031726231756443208850082191198787792966516790381991"
              "77502076899763751166291092085666022362525614129374702633"
              "26262930887668422949051881895212412718444016917144560705"
              "45675251775747156453237145919794089496168502517202869160"
              "78674893099371444940800865897607102159386345313384716752"
              "18590012064772045092956919481")
        q = 1393384845225358996250882900535419012502712821577
        dsaBlob = (
            common.NS('ssh-dss') + common.MP(p) + common.MP(q) +
            common.MP(4) + common.MP(5))
        dsaKey = keys.Key.fromString(dsaBlob)
        badKey = common.NS('ssh-bad')
        self.assertTrue(rsaKey.isPublic())
        self.assertEqual(rsaKey.data(), {'e': 3L, 'n': 7L})
        self.assertTrue(dsaKey.isPublic())
        self.assertEqual(dsaKey.data(), {'p': p, 'q': q, 'g': 4L, 'y': 5L})
        self.assertBadKey(badKey, 'Unknown blob type: \'ssh-bad\'')

    def test_fromString_BLOB_blob_type_non_ascii(self):
        """
        Raise with printable information for the bad type,
        even if blob type has non-ascii data.
        """
        badBlob = common.NS('ssh-\xbd\xbd\xbd')
        self.assertBadKey(
            badBlob,
            'Unknown blob type: \'ssh-\\xbd\\xbd\\xbd\''
            )

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

    def test_fromString_PUBLIC_OPENSSH_invalid_payload(self):
        """
        Raise an exception when key blob has a bad format.
        """
        self.assertKeyParseError('ssh-rsa AAAAB3NzaC1yc2EA')

    def test_fromString_PUBLIC_OPENSSH_DSA(self):
        """
        Can load a public OpenSSH in DSA format.
        """
        sut = Key.fromString(OPENSSH_DSA_PUBLIC)

        self.checkParsedDSAPublic1024(sut)

    def test_fromString_OpenSSH(self):
        """
        Test that keys are correctly generated from OpenSSH strings.
        """
        self._testPublicPrivateFromString(
            keydata.publicRSA_openssh,
            keydata.privateRSA_openssh, 'RSA', keydata.RSAData)
        self.assertEqual(
            keys.Key.fromString(
                keydata.privateRSA_openssh_encrypted,
                passphrase='encrypted'),
            keys.Key.fromString(keydata.privateRSA_openssh))
        self.assertEqual(
            keys.Key.fromString(
                keydata.privateRSA_openssh_alternate),
            keys.Key.fromString(keydata.privateRSA_openssh))
        self._testPublicPrivateFromString(
            keydata.publicDSA_openssh,
            keydata.privateDSA_openssh, 'DSA', keydata.DSAData)

    def test_fromString_PRIVATE_OPENSSH_with_whitespace(self):
        """
        If key strings have trailing whitespace, it should be ignored.
        """
        # from Twisted bug #3391, since our test key data doesn't have
        # an issue with appended newlines
        privateDSAData = """-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDylESNuc61jq2yatCzZbenlr9llG+p9LhIpOLUbXhhHcwC6hrh
EZIdCKqTO0USLrGoP5uS9UHAUoeN62Z0KXXWTwOWGEQn/syyPzNJtnBorHpNUT9D
Qzwl1yUa53NNgEctpo4NoEFOx8PuU6iFLyvgHCjNn2MsuGuzkZm7sI9ZpQIVAJiR
9dPc08KLdpJyRxz8T74b4FQRAoGAGBc4Z5Y6R/HZi7AYM/iNOM8su6hrk8ypkBwR
a3Dbhzk97fuV3SF1SDrcQu4zF7c4CtH609N5nfZs2SUjLLGPWln83Ysb8qhh55Em
AcHXuROrHS/sDsnqu8FQp86MaudrqMExCOYyVPE7jaBWW+/JWFbKCxmgOCSdViUJ
esJpBFsCgYEA7+jtVvSt9yrwsS/YU1QGP5wRAiDYB+T5cK4HytzAqJKRdC5qS4zf
C7R0eKcDHHLMYO39aPnCwXjscisnInEhYGNblTDyPyiyNxAOXuC8x7luTmwzMbNJ
/ow0IqSj0VF72VJN9uSoPpFd4lLT0zN8v42RWja0M8ohWNf+YNJluPgCFE0PT4Vm
SUrCyZXsNh6VXwjs3gKQ
-----END DSA PRIVATE KEY-----"""
        self.assertEqual(keys.Key.fromString(privateDSAData),
                         keys.Key.fromString(privateDSAData + '\n'))

    def test_fromString_PRIVATE_OPENSSH_newer(self):
        """
        Newer versions of OpenSSH generate encrypted keys which have a longer
        IV than the older versions. These newer keys are also loaded.
        """
        key = keys.Key.fromString(keydata.privateRSA_openssh_encrypted_aes,
                                  passphrase='testxp')
        self.assertEqual(key.type(), 'RSA')
        key2 = keys.Key.fromString(
            keydata.privateRSA_openssh_encrypted_aes + '\n',
            passphrase='testxp')
        self.assertEqual(key, key2)

    def test_fromString_PRIVATE_OPENSSH_not_encrypted_with_passphrase(self):
        """
        When loading a unencrypted OpenSSH private key with passhphrase
        will raise BadKeyError.
        """

        with self.assertRaises(BadKeyError) as context:
            Key.fromString(OPENSSH_RSA_PRIVATE, passphrase='pass')

        self.assertEqual(
            'OpenSSH key not encrypted',
            context.exception.message)

    def test_toString_OPENSSH(self):
        """
        Test that the Key object generates OpenSSH keys correctly.
        """
        key = keys.Key.fromString(keydata.privateRSA_lsh)

        self.assertEqual(key.toString('openssh'), keydata.privateRSA_openssh)
        self.assertEqual(
            key.toString('openssh', 'encrypted'),
            keydata.privateRSA_openssh_encrypted)
        self.assertEqual(
            key.public().toString('openssh'),
            keydata.publicRSA_openssh[:-8])
        self.assertEqual(
            key.public().toString('openssh', 'comment'),
            keydata.publicRSA_openssh)

        key = keys.Key.fromString(keydata.privateDSA_lsh)

        self.assertEqual(key.toString('openssh'), keydata.privateDSA_openssh)
        self.assertEqual(
            key.public().toString('openssh', 'comment'),
            keydata.publicDSA_openssh)
        self.assertEqual(
            key.public().toString('openssh'), keydata.publicDSA_openssh[:-8])

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

        self.assertEqual(1024, sut.size())
        self.assertEqual('RSA', sut.type())
        self.assertTrue(sut.isPublic())
        data = sut.data()
        self.assertEqual(65537L, data['e'])

    def test_fromString_PUBLIC_SSHCOM_DSA(self):
        """
        Can load a public SSH.com in DSA format.
        """
        sut = Key.fromString(SSHCOM_DSA_PUBLIC)

        self.checkParsedDSAPublic1024(sut)

    def test_fromString_PUBLIC_SSHCOM_no_end_tag(self):
        """
        Raise an exception when there is no END tag.
        """
        content = '---- BEGIN SSH2 PUBLIC KEY ----'

        self.assertBadKey(content, 'Fail to find END tag for SSH.com key.')

        content = '---- BEGIN SSH2 PUBLIC KEY ----\nnext line'

        self.assertBadKey(content, 'Fail to find END tag for SSH.com key.')

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

        result = sut.toString(type='openssh')
        self.assertEqual(result, OPENSSH_RSA_PRIVATE)

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_OPENSSH_DSA(self):
        """
        Can load a private OpenSSH DSA key.
        """
        sut = Key.fromString(OPENSSH_DSA_PRIVATE)

        self.checkParsedDSAPrivate1024(sut)

    def test_fromString_PRIVATE_OPENSSH_ECDSA(self):
        """
        Can load a private OPENSSH ECDSA.
        """
        sut = Key.fromString(keydata.privateECDSA_256_openssh)

        self.assertEqual('EC', sut.type())

    def test_fromString_PRIVATE_OPENSSH_short(self):
        """
        Raise an error when private OpenSSH key is too short.
        """
        content = '-----BEGIN RSA PRIVATE KEY-----'

        self.assertKeyIsTooShort(content)

        content = '-----BEGIN RSA PRIVATE KEY-----\nAnother Line'

        self.assertBadKey(
            content,
            'Failed to decode key (Bad Passphrase?): '
            'Short octet stream on tag decoding')

    def test_fromString_PRIVATE_OPENSSH_bad_encoding(self):
        """
        Raise an error when private OpenSSH key data can not be decoded.
        """
        content = '-----BEGIN RSA PRIVATE KEY-----\nAnother Line\nLast'

        self.assertKeyParseError(content)

    def test_fromString_PRIVATE_SSHCOM_unencrypted_with_passphrase(self):
        """
        When loading a unencrypted SSH.com private key with passhphrase
        will raise BadKeyError.
        """

        with self.assertRaises(BadKeyError) as context:
            Key.fromString(SSHCOM_RSA_PRIVATE_NO_PASSWORD, passphrase='pass')

        self.assertEqual(
            'SSH.com key not encrypted',
            context.exception.message)

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
        reference = Key.fromString(OPENSSH_RSA_PRIVATE)

        sut = Key.fromString(
            SSHCOM_RSA_PRIVATE_WITH_PASSWORD, passphrase='chevah')

        self.assertEqual(reference, sut)

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

    def test_fromString_X509_PEM_invalid_format(self):
        """
        It fails to load invalid formated X509 PEM certificate.
        """
        data = """-----BEGIN CERTIFICATE-----
MIIBNDCB66ADAgECAgEBMAoGCCqGSM49BAMCMDQxCzAJBgNVBAYTAkdCMQ8wDQYD
8J4wCgYIKoZIzj0EAwIDOAAwNQIZANYXcrq622yfNJSyjlzDvk3w59IaOlljqwIY
Gt7MBDMYYr8yfcZS94pZEUfhebR3CYAZ
-----END CERTIFICATE-----
"""
        with self.assertRaises(BadKeyError) as context:
            Key.fromString(data)

        self.assertStartsWith(
            "Failed to load certificate. [('asn1 encoding routines'",
            context.exception.message,
            )

    def test_fromString_X509_PEM_EC(self):
        """
        EC public key from an X509 PEM certificate are not supported.
        """
        data = """-----BEGIN CERTIFICATE-----
MIIBNDCB66ADAgECAgEBMAoGCCqGSM49BAMCMDQxCzAJBgNVBAYTAkdCMQ8wDQYD
VQQKEwZDaGV2YWgxFDASBgNVBAMTC3Rlc3QtZWMtc3NoMB4XDTE5MDYxOTEyNTQw
MFoXDTIwMDYxOTEyNTQwMFowNDELMAkGA1UEBhMCR0IxDzANBgNVBAoTBkNoZXZh
aDEUMBIGA1UEAxMLdGVzdC1lYy1zc2gwSTATBgcqhkjOPQIBBggqhkjOPQMBAQMy
AARzpUpSPLojoyouYH7HhSFV661wUKrRVqLyJlBb1cWU8f4wLZsGkXymZpAPClwu
8J4wCgYIKoZIzj0EAwIDOAAwNQIZANYXcrq622yfNJSyjlzDvk3w59IaOlljqwIY
Gt7MBDMYYr8yfcZS94pZEUfhebR3CYAZ
-----END CERTIFICATE-----
"""
        with self.assertRaises(BadKeyError) as context:
            Key.fromString(data)

        self.assertEqual(
            'Unsupported key found in the certificate.',
            context.exception.message,
            )

    def test_fromString_X509_PEM_RSA(self):
        """
        It can extract RSA public key from an X509 PEM certificate
        """
        data = """-----BEGIN CERTIFICATE-----
MIICaDCCAdGgAwIBAgIBDjANBgkqhkiG9w0BAQUFADBGMQswCQYDVQQGEwJHQjEP
MA0GA1UEChMGQ2hldmFoMRIwEAYDVQQLEwlDaGV2YWggQ0ExEjAQBgNVBAMTCUNo
ZXZhaCBDQTAeFw0xNjA2MTUxNDM4MDBaFw0zNjA2MTUxNDM4MDBaMEgxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQKEwZDaGV2YWgxFDASBgNVBAsTC0NoZXZhaCBUZXN0MRIw
EAYDVQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAM6h
lRh3woxhut7nNkjBH5Xp07b5wJhVLjoEdtFuq3uBzOSghaEpapeL0/M4Rpw9ANjy
ulGy7rwJI9Me95aG53BrjMbBKk1qaHuNXa3PJjcgVmPelwPcbzk5Wl4E57dLN+eh
4Rf/Qyi9HBdtrDf19OzBmBs7W7pO9LPo5/usHlyVAgMBAAGjZDBiMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly9sb2NhbGhvc3Q6
ODA4MC9zb21lLWNoaWxkL2NhLmNybDARBglghkgBhvhCAQEEBAMCBkAwDQYJKoZI
hvcNAQEFBQADgYEAM8Ro0XZeIrR7+fi4pGMdqTAdNFNd2O86YgzpvGpUIbhmJnty
1k0aF2QNot4M6i6OhVQEwL4Ph/l6pbOnusv238nuzHyDHFWNPy1wV02hjacXF9EW
JZQaMjV9XxNTFOlNUTWswff3uE677wSVDPSuNkxo2FLRcGfPUxAQGsgL5Ts=
-----END CERTIFICATE-----
"""

        sut = Key.fromString(data)

        self.assertTrue(sut.isPublic())
        self.assertEqual('RSA', sut.type())
        self.assertEqual(1024, sut.size())

        components = sut.data()
        self.assertEqual(65537L, components['e'])
        n = long(
            '14510135000543456324610075074919561379239940215773254633039625814'
            '50191438083097108908667737243399472490927083264564327600896049375'
            '92092816317169486450111458914839337717035721053431064458247582292'
            '33425907841901335798792724220900289242783534069221630733833594745'
            '1002424312049140771718167143894887320401855011989L'
            )
        self.assertEqual(n, components['n'])

    def test_fromString_X509_PEM_DSA(self):
        """
        It can extract DSA public key from an X509 PEM certificate
        """
        data = """-----BEGIN CERTIFICATE-----
MIICsDCCAm6gAwIBAgIBATALBglghkgBZQMEAwIwPTELMAkGA1UEBhMCR0IxDzAN
BgNVBAoTBkNoZXZhaDEdMBsGA1UEAxMUdGVzdC1zc2gtY29udmVyc3Rpb24wHhcN
MTkwNjE5MTIzNjAwWhcNMjAwNjE5MTIzNjAwWjA9MQswCQYDVQQGEwJHQjEPMA0G
A1UEChMGQ2hldmFoMR0wGwYDVQQDExR0ZXN0LXNzaC1jb252ZXJzdGlvbjCCAbcw
ggEsBgcqhkjOOAQBMIIBHwKBgQD/HJmstkyONrDh2iSafsRqxAzRG4dIUa70PdsE
gfMYBx95Nk1vhwGFyEQyCy305b2mgLG9+nkFkaLiD5UnoBbmO1NCggXlSNoe3ezq
akr80gV6dCwbM4T7B7lc3S0Eh5OJ2F5DKewzT65QyRrnkfECFlvjJqpeywhfucvg
nadoCwIVAIA92hGRUbX41P8zCqRBAMiEChlzAoGBALg27DhLThHhJHWdFX2gZYTm
NMjv/Z7mHCAda8/uqNXjAz97jI9w6KCSYIC7qiyl0lwGuW7kGqNCtnsZyxKWQzTy
HoONu9gfAmAxZbI3TuE49fYZJ/0m0mXyPpCg0VIeFJVcS6lA2W51UD1JrvCrUb1M
1SgNW+V/VHw6M54e+v1SA4GEAAKBgC/cCWpZpebhiEThZLd+eodR9vCntB8sIzrA
0JRCmi4t8vBOxLNAZQE7WdPWXZJA7d43+6B4//DZH+GOt6EoxLyPxcqM+GHqa99i
EwIuTKCIG6ucDtvzMSgwvYVFugfYaoJvu0Okc+6elNywpk9t3HLH5p2QbpPXPYgO
SH6qmzKdMAsGCWCGSAFlAwQDAgMvADAsAhR2vu0VK+loePjKDZcalym8vjgwkwIU
HNkVqo/9uKhSFkhbG6uKWUnOky0=
-----END CERTIFICATE-----
"""

        sut = Key.fromString(data)

        self.assertTrue(sut.isPublic())
        self.assertEqual('DSA', sut.type())
        self.assertEqual(1024, sut.size())

        components = sut.data()
        y = long(
            '33608096932577498834618892325416552088960771123656082234885710486'
            '75507586904443594643612585160476637613084634099891307779753871384'
            '19072984388914093315900417736990449366567905225558889080164633948'
            '75642330307431599331123161679260711587324602448450132263105327567'
            '324900691359269978674482129301723462636106625693'
            )
        p = long(
            '17914554197956231476032656039682646299975055883332311875135017227'
            '52180243454588892360869849018970437236700881503241838175380166833'
            '56570852141623851276212449051705325396966909384918507908491159872'
            '81118556760058432354600693107636249903432532125207156471720334839'
            '5401646777661899361981163845950810903143363602443'
            )
        g = long(
            '12935985053463672691492638315705405640647316377002915690069266627'
            '73032720642846501430445126372712764104983906841935717997673558164'
            '74657088881395785073303554687569602926262408886111665706815822813'
            '14448994749901282518897434324098506093655990924057550618491224583'
            '7106339202519842112263186663472095769544164572498'
            )
        self.assertEqual(y, components['y'])
        self.assertEqual(p, components['p'])
        self.assertEqual(g, components['g'])
        self.assertEqual(
            732130160578857514768194964362219084190055012723L, components['q'])

    def test_toString_SSHCOM_RSA_private_without_encryption(self):
        """
        Can export a private RSA SSH.com without without encryption.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type='sshcom')

        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

        # Check that it looks like SSH.com private key.
        #self.assertEqual(SSHCOM_RSA_PRIVATE_NO_PASSWORD, result)

    def test_toString_SSHCOM_RSA_private_encrypted(self):
        """
        Can export an encrypted private RSA SSH.com.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type='sshcom', extra='chevah')

        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result, passphrase='chevah')
        self.assertEqual(sut, reloaded)

        # Check that it looks like SSH.com private key.
        #self.assertEqual(SSHCOM_RSA_PRIVATE_WITH_PASSWORD, result)

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
        reference = Key.fromString(OPENSSH_RSA_PRIVATE)
        sut = Key.fromString(PUTTY_RSA_PRIVATE_NO_PASSWORD)

        self.assertEqual(reference, sut)
        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_not_encrypted_with_passphrase(self):
        """
        When loading a unencrypted PuTTY private key with passhphrase
        will raise BadKeyError.
        """
        with self.assertRaises(BadKeyError) as context:
            Key.fromString(PUTTY_RSA_PRIVATE_NO_PASSWORD, passphrase='pass')

        self.assertEqual(
            'PuTTY key not encrypted',
            context.exception.message)

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
            content, 'Unsupported key type: \'ssh-bad\'')

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
            content, 'Unsupported encryption type: \'aes126-cbc\'')

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
            (
                'Mismatch key type. Header has \'ssh-rsa\','
                ' public has \'ssh-dss\''),
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
        reference = Key.fromString(PUTTY_RSA_PRIVATE_NO_PASSWORD)

        result = reference.toString(
            type='putty', comment='imported-openssh-key')

        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(reference, reloaded)

        # And if we serialized again, we get the same thing.
        #self.assertEqual(PUTTY_RSA_PRIVATE_NO_PASSWORD, result)

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

    def test_toString_PUTTY_public(self):
        """
        Can export to public RSA Putty.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE).public()

        result = sut.toString(type='putty')

        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_fromString_LSH(self):
        """
        Test that keys are correctly generated from LSH strings.
        """
        self._testPublicPrivateFromString(
            keydata.publicRSA_lsh,
            keydata.privateRSA_lsh, 'RSA', keydata.RSAData)
        self._testPublicPrivateFromString(
            keydata.publicDSA_lsh,
            keydata.privateDSA_lsh, 'DSA', keydata.DSAData)

        sexp = sexpy.pack([['public-key', ['bad-key', ['p', '2']]]])
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
            data='{' + base64.encodestring(sexp) + '}')

        sexp = sexpy.pack([['private-key', ['bad-key', ['p', '2']]]])
        self.assertRaises(
            keys.BadKeyError, keys.Key.fromString, sexp)

    def test_toString_LSH(self):
        """
        Test that the Key object generates LSH keys correctly.
        """
        key = keys.Key.fromString(keydata.privateRSA_openssh)
        self.assertEqual(key.toString('lsh'), keydata.privateRSA_lsh)
        self.assertEqual(
            key.public().toString('lsh'), keydata.publicRSA_lsh)
        key = keys.Key.fromString(keydata.privateDSA_openssh)
        self.assertEqual(key.toString('lsh'), keydata.privateDSA_lsh)
        self.assertEqual(
            key.public().toString('lsh'), keydata.publicDSA_lsh)

    def test_toString_AGENTV3(self):
        """
        Test that the Key object generates Agent v3 keys correctly.
        """
        key = keys.Key.fromString(keydata.privateRSA_openssh)
        self.assertEqual(key.toString('agentv3'), keydata.privateRSA_agentv3)
        key = keys.Key.fromString(keydata.privateDSA_openssh)
        self.assertEqual(key.toString('agentv3'), keydata.privateDSA_agentv3)

    def test_fromString_AGENTV3(self):
        """
        Test that keys are correctly generated from Agent v3 strings.
        """
        self._testPrivateFromString(
            keydata.privateRSA_agentv3, 'RSA', keydata.RSAData)
        self._testPrivateFromString(
            keydata.privateDSA_agentv3, 'DSA', keydata.DSAData)
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
            '\x00\x00\x00\x07ssh-foo' + '\x00\x00\x00\x01\x01' * 5)

    def test_getKeyFormat_unknown(self):
        """
        Inform using a human readable text that format is not known.
        """
        result = Key.getKeyFormat('no-such-format')

        self.assertEqual('Unknown format', result)

    def test_getKeyFormat_known(self):
        """
        Return the human readable description of key format.
        """

        result = Key.getKeyFormat(SSHCOM_RSA_PUBLIC)

        self.assertEqual('SSH.com Public', result)

    def test_guessStringType_unknown(self):
        """
        None is returned when could not detect key type.
        """
        content = mk.ascii()

        result = Key._guessStringType(content)

        self.assertIsNone(result)

    def test_guessStringType_PEM_certificate(self):
        """
        PEM certificates are recognized as public keys.
        """
        content = (
            '-----BEGIN CERTIFICATE-----\n'
            'CONTENT\n'
            '-----END CERTIFICATE-----\n'
            )

        result = Key._guessStringType(content)

        self.assertEqual('public_x509', result)

    def test_guessStringType_private_OpenSSH_RSA(self):
        """
        Can recognize an OpenSSH RSA private key.
        """
        result = Key._guessStringType(OPENSSH_RSA_PRIVATE)

        self.assertEqual('private_openssh', result)

    def test_guessStringType_private_OpenSSH_DSA(self):
        """
        Can recognize an OpenSSH DSA private key.
        """
        result = Key._guessStringType(OPENSSH_DSA_PRIVATE)

        self.assertEqual('private_openssh', result)

    def test_guessStringType_private_OpenSSH_ECDSA(self):
        """
        Can recognize an OpenSSH ECDSA private key.
        """
        result = Key._guessStringType(keydata.privateECDSA_256_openssh)

        self.assertEqual('private_openssh', result)

    def test_guessStringType_public_OpenSSH(self):
        """
        Can recognize an OpenSSH public key.
        """
        result = Key._guessStringType(OPENSSH_RSA_PUBLIC)

        self.assertEqual('public_openssh', result)

    def test_guessStringType_public_OpenSSH_ECDSA(self):
        """
        Can recognize an OpenSSH public key.
        """
        result = Key._guessStringType(keydata.publicECDSA_256_openssh)

        self.assertEqual('public_openssh', result)

        result = Key._guessStringType(keydata.publicECDSA_384_openssh)

        self.assertEqual('public_openssh', result)

        result = Key._guessStringType(keydata.publicECDSA_521_openssh)

        self.assertEqual('public_openssh', result)

    def test_guessStringType_private_SSHCOM(self):
        """
        Can recognize an SSH.com private key.
        """
        result = Key._guessStringType(SSHCOM_RSA_PRIVATE_NO_PASSWORD)

        self.assertEqual('private_sshcom', result)

    def test_guessStringType_public_SSHCOM(self):
        """
        Can recognize an SSH.com public key.
        """
        result = Key._guessStringType(SSHCOM_RSA_PUBLIC)

        self.assertEqual('public_sshcom', result)

    def test_guessStringType_putty(self):
        """
        Can recognize a Putty private key.
        """
        result = Key._guessStringType(PUTTY_RSA_PRIVATE_NO_PASSWORD)

        self.assertEqual('private_putty', result)

    def test_generate_no_key_type(self):
        """
        An error is raised when generating a key with unknown type.
        """
        with self.assertRaises(KeyCertException) as context:
            Key.generate(key_type=None)

        self.assertEqual(
            'Unknown key type "not-specified".', context.exception.message)

    def test_generate_unknown_type(self):
        """
        An error is raised when generating a key with unknown type.
        """
        with self.assertRaises(KeyCertException) as context:
            Key.generate(key_type='bad-type')

        self.assertEqual(
            'Unknown key type "bad-type".', context.exception.message)

    @attr('slow')
    def test_generate_rsa(self):
        """
        Check generation of an RSA key with a case insensitive type name.
        """
        key = Key.generate(key_type='rSA', key_size=1024)

        self.assertEqual('RSA', key.type())
        self.assertEqual(1024, key.size())

    @attr('slow')
    def test_generate_dsa(self):
        """
        Check generation of a DSA key with a case insensitive type name.
        """
        key = Key.generate(key_type='dSA', key_size=1024)

        self.assertEqual('DSA', key.type())
        self.assertEqual(1024, key.size())

    def test_generate_failed(self):
        """
        A ServerError is raised when it fails to generate the key.
        """
        with self.assertRaises(KeyCertException) as context:
            Key.generate(key_type='dSa', key_size=512)

        self.assertEqual(
            'Failed to generate SSH key. '
            'Key size must be 1024 or 2048 or 3072 bits.',
            context.exception.message)

        with self.assertRaises(KeyCertException) as context:
            Key.generate(key_type='rsa', key_size=511)

        self.assertEqual(
            'Failed to generate SSH key. key_size must be at least 512-bits.',
            context.exception.message)


class Test_generate_ssh_key_parser(ChevahTestCase, CommandLineMixin):
    """
    Unit tests for generate_ssh_key_parser.
    """

    def setUp(self):
        super(Test_generate_ssh_key_parser, self).setUp()
        self.parser = ArgumentParser(prog='test-command')
        self.subparser = self.parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')

    def test_default(self):
        """
        It only need a subparser and sub-command name.
        """
        generate_ssh_key_parser(self.subparser, 'key-gen')

        options = self.parseArguments(['key-gen'])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key_comment': None,
            'key_file': None,
            'key_size': 2048,
            'key_type': 'rsa',
            'key_skip': False,
            }, options)

    def test_value(self):
        """
        Options are parsed from the command line.
        """
        generate_ssh_key_parser(self.subparser, 'key-gen')

        options = self.parseArguments([
            'key-gen',
            '--key-comment', 'some comment',
            '--key-file=id_dsa',
            '--key-size', '1024',
            '--key-type', 'dsa',
            '--key-skip',
            ])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key_comment': 'some comment',
            'key_file': 'id_dsa',
            'key_size': 1024,
            'key_type': 'dsa',
            'key_skip': True,
            }, options)

    def test_default_overwrite(self):
        """
        You can change default values.
        """
        generate_ssh_key_parser(
            self.subparser, 'key-gen',
            default_key_size=1024,
            default_key_type='dsa',
            )

        options = self.parseArguments(['key-gen'])

        self.assertNamespaceEqual({
            'sub_command': 'key-gen',
            'key_comment': None,
            'key_file': None,
            'key_size': 1024,
            'key_type': 'dsa',
            'key_skip': False,
            }, options)


class Testgenerate_ssh_key(ChevahTestCase, CommandLineMixin):
    """
    Tests for generate_ssh_key.
    """

    def setUp(self):
        super(Testgenerate_ssh_key, self).setUp()
        self.parser = ArgumentParser(prog='test-command')
        self.sub_command_name = 'gen-ssh-key'
        subparser = self.parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')
        generate_ssh_key_parser(subparser, self.sub_command_name)

    def assertPathEqual(self, expected, actual):
        """
        Check that pats are equal.
        """
        if self.os_family == 'posix':
            expected = expected.encode('utf-8')
        self.assertEqual(expected, actual)

    def test_generate_ssh_key_custom_values(self):
        """
        When custom values are provided, the key is generated using those
        values.
        """
        file_name = mk.ascii()
        file_name_pub = file_name + b'.pub'
        options = self.parseArguments([
            self.sub_command_name,
            '--key-size=512',
            '--key-type=RSA',
            '--key-file=' + file_name,
            '--key-comment=this is a comment',
            ])
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(
            options, open_method=open_method)

        self.assertEqual('RSA', key.type())
        self.assertEqual(512, key.size())

        # First it writes the private key.
        first_file = open_method.calls.pop(0)
        self.assertPathEqual(file_name, first_file['path'])
        self.assertEqual('wb', first_file['mode'])
        self.assertEqual(
            key.toString('openssh'), first_file['stream'].getvalue())

        # Second it writes the public key.
        second_file = open_method.calls.pop(0)
        self.assertPathEqual(file_name_pub, second_file['path'])
        self.assertEqual('wb', second_file['mode'])
        self.assertEqual(
            key.public().toString('openssh', 'this is a comment'),
            second_file['stream'].getvalue())

        self.assertEqual(
            u'SSH key of type "rsa" and length "512" generated as public '
            u'key file "%s" and private key file "%s" '
            u'having comment "this is a comment".' % (
                file_name_pub, file_name),
            message,
            )
        self.assertEqual(0, exit_code)

    def test_generate_ssh_key_default_values(self):
        """
        When no path and no comment are provided, it will use default
        values.
        """
        options = self.parseArguments([
            self.sub_command_name,
            '--key-size=1024',
            '--key-type=RSA',
            ])
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(
            options, open_method=open_method)

        self.assertContains('SSH key of type', message)
        self.assertEqual(0, exit_code)
        self.assertEqual('RSA', key.type())
        self.assertEqual(1024, key.size())

        # First it writes the private key.
        first_file = open_method.calls.pop(0)
        self.assertPathEqual(u'id_rsa', first_file['path'])
        self.assertEqual('wb', first_file['mode'])
        self.assertEqual(
            key.toString('openssh'), first_file['stream'].getvalue())

        # Second it writes the public key.
        second_file = open_method.calls.pop(0)
        self.assertPathEqual(u'id_rsa.pub', second_file['path'])
        self.assertEqual('wb', second_file['mode'])
        self.assertEqual(
            key.public().toString('openssh'), second_file['stream'].getvalue())

        # Message informs what default values were used.
        self.assertEqual(
            u'SSH key of type "rsa" and length "1024" generated as public '
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
        options = self.parseArguments([
            self.sub_command_name,
            '--key-type=RSA',
            '--key-size=2048',
            '--key-file', path,
            ])
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(
            options, open_method=open_method)

        self.assertEqual(1, exit_code)
        self.assertEqual(u'Private key already exists. %s' % path, message)
        # Open is not called.
        self.assertIsEmpty(open_method.calls)

    def test_generate_ssh_key_private_exist_skip(self):
        """
        On skip, will not generate the key if private file already
        exists and exit without error.
        """
        self.test_segments = mk.fs.createFileInTemp()
        path = mk.fs.getRealPathFromSegments(self.test_segments)
        options = self.parseArguments([
            self.sub_command_name,
            '--key-skip',
            '--key-type=RSA',
            '--key-size=2048',
            '--key-file', path,
            ])
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(
            options, open_method=open_method)

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
        options = self.parseArguments([
            self.sub_command_name,
            '--key-type=RSA',
            '--key-size=2048',
            # path is for public key, but we pass the private path.
            '--key-file', path[:-4],
            ])
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(
            options, open_method=open_method)

        self.assertEqual(1, exit_code)
        self.assertEqual(u'Public key already exists. %s' % path, message)
        # Open is not called.
        self.assertIsEmpty(open_method.calls)

    def test_generate_ssh_key_fail_to_write(self):
        """
        Will return an error when failing to write the key.
        """
        options = self.parseArguments([
            self.sub_command_name,
            '--key-type=RSA',
            '--key-size=1024',
            '--key-file', 'no-such-parent/ssh.key',
            ])

        exit_code, message, key = generate_ssh_key(options)

        self.assertEqual(1, exit_code)
        self.assertEqual(
            "[Errno 2] No such file or directory: 'no-such-parent/ssh.key'",
            message)
