# Copyright (c) 2014 Adi Roiban.
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
Test for SSH keys management.
"""
import textwrap
from argparse import ArgumentParser
from io import BytesIO

from chevah_compat.testing import ChevahTestCase, mk
from nose.plugins.attrib import attr

# Twisted test compatibility.
from chevah_keycert import _path, common
from chevah_keycert import ssh as keys
from chevah_keycert.exceptions import BadKeyError, EncryptedKeyError, KeyCertException
from chevah_keycert.ssh import Key, generate_ssh_key, generate_ssh_key_parser
from chevah_keycert.tests import keydata
from chevah_keycert.tests.helpers import CommandLineMixin

OPENSSH_RSA_PRIVATE = b"""-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

# Converted from old format using OpenSSH without a password.
# $ ssh-keygen -e -p -f OPENSSH_RSA_PRIVATE.key
OPENSSH_V1_RSA_PRIVATE = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAuH1erUmpA0gemaL8oC7H9YgvT97SR3j0ygD5DwFs5buQUR3JgLtL
k45+xoa6cW441jMA1TdDsc8O7XiNDhCFZKZ5XMjOi+ZhpPl+i3OPpQH6dWMQkfaPfhVzFk
iT99o0cCPuC4VmMZ2FJXbwDuSw8/UHkdMiopsHI0U6Bev46S8AAAH4y/dH2sv3R9oAAAAH
c3NoLXJzYQAAAIEAuH1erUmpA0gemaL8oC7H9YgvT97SR3j0ygD5DwFs5buQUR3JgLtLk4
5+xoa6cW441jMA1TdDsc8O7XiNDhCFZKZ5XMjOi+ZhpPl+i3OPpQH6dWMQkfaPfhVzFkiT
99o0cCPuC4VmMZ2FJXbwDuSw8/UHkdMiopsHI0U6Bev46S8AAAADAQABAAAAgAgeXEA78Z
gXYGFabsuNw3bmm05ke9RxWjRZfpxOb8BcVKl9KhTkKRtBNgr+es3rD809SVgYqn30oq+I
kox/5Z7JGZzPSdcX6Z6CeR083Bh2gWFRRBF0unzrMlk9eaGOym+q0QU51ldCJ7P9OR4ad/
K/0UfzuKaAftzcECQ5f+oBAAAAQH+ARfXlS8UUPQODJvSJLeJRfIoup2uJ8XbRMz/Kdiz/
bS6h2FKGzWp8QfuzLIuH94GMrinThp1h6g9lOB3C3TEAAABBAOgCdF0L7lLKOtnUlBRZSR
qmJgciEWrqRa0abeRYmfQjEIG0WEa+ohYnBkgCN/q1MoxSTpuMb2nsml61dSxOIMEAAABB
AMuRA1NheNl5urb0MzPGwIKu3dv8doh0bjpA1G9Wyt2MAck4oZfQS6r3UYUcaZdtRHKlqQ
f0cwBWxmvutBv4le8AAAAAAQID
-----END OPENSSH PRIVATE KEY-----"""

# Converted from old format using OpenSSH with `test` as password.
# $ ssh-keygen -e -p -f OPENSSH_RSA_PRIVATE.key
OPENSSH_V1_ENCRYPTED_RSA_PRIVATE = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCO5u6Nze
CPk3e+vkL9MmvWAAAAEAAAAAEAAACXAAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakD
SB6ZovygLsf1iC9P3tJHePTKAPkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI
0OEIVkpnlcyM6L5mGk+X6Lc4+lAfp1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz
9QeR0yKimwcjRToF6/jpLwAAAgDuID/fk0osaBUXQ+M32lA677YjC9BX5bSwKHNdbaH/eD
H5T4mNZNe8IvZXsYGsVXKT5yaRP/19A/5pVivnTn2n0dOZ0tbfnqrPLJnEdPPTlLVv+YaR
+TZYRYfydOXpZ44MsJAzmOmCWVIlDNratEt/zoiqhF2T3q4ODFEABfDQ3LixRx+Jk90icy
FrL7DuDLsTdjXLnmUSh7Ytzd9v8XrQ8ku98EvOzqCCneYguYt2zHrRVd+jWivJ7Pdv86lg
kksqxIlY7TV+wqcbYvLDuZF6iP3jWAGoQYSUJpqVwp0PLz53hzxwcLMEg+V93e9fYiQjsE
psoQ/y8ZGmBIGqkAj+BC9Y6DXFPmstv0yHlSoB/A4FwVerZiVu4G239LF8Wt6gfAU7Bu7j
yvWKic87GsONUvp8iKFntCFgeX4aa9bVsl4N9APzEBPsj2ni4E3+UYYovGBo8jlmxBAj3V
evUSgiQfOTIM8UkZfk6plXchJTmshIeL1SMyjdNF2ziVh72T1RCOs/905gXXvw+Bl+zdtJ
5sRcoQii4HcPjK0WUZaSM/5LsxSsqDt+nBVoaq7k24ITTjXdHIuiT1YnKFjErzD3bznosW
wNe7YoLXxnuszUFaBAWthJuOsE1JVAScqo7oClPc1CHX8qEZz5vihkEploAOGe0hj5Kjt6
vLDBLhI7ag==
-----END OPENSSH PRIVATE KEY-----"""

OPENSSH_RSA_PUBLIC = (
    b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTKA"
    b"PkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk+X6Lc4+lAf"
    b"p1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcjRToF6/jpLw=="
)

PKCS1_RSA_PUBLIC = b"""-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALh9Xq1JqQNIHpmi/KAux/WIL0/e0kd49MoA+Q8BbOW7kFEdyYC7S5OO
fsaGunFuONYzANU3Q7HPDu14jQ4QhWSmeVzIzovmYaT5fotzj6UB+nVjEJH2j34V
cxZIk/faNHAj7guFZjGdhSV28A7ksPP1B5HTIqKbByNFOgXr+OkvAgMBAAE=
-----END RSA PUBLIC KEY-----"""

OPENSSH_DSA_PRIVATE = b"""-----BEGIN DSA PRIVATE KEY-----
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
-----END DSA PRIVATE KEY-----"""

# Converted from old format using OpenSSH without a password.
# $ ssh-keygen -e -p -f OPENSSH_DSA_PRIVATE.key
OPENSSH_V1_DSA_PRIVATE = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQDOwkKGnmVZ9bRl7ZCn/wSELV0n5ELsqVZFOtBpHleEOitsvjEBBbTKX0fZ83va
MVnJFVw3DQSbi192krvk909Y6h3HVO2MKBRd9t29fr26VvCZQOxR4fzkPuL+Px4+ShqE17
1sOzsuEDt0Mkxf152QxrA2vPowkj7fmzRH5xgDTQAAABUAhhv+WNJRyWjpOI3CiIX71vJp
8UkAAACAXA+TAGCmF2ZeNZN04mgxeyT34IAw37NGmLLP/byi86dKcdz5htqPiOWcNmFzrA
7a0o+erE3B+miwEm2sVz+eVWfNOCJQalHUqRrk1iV542FL0BCePiJa91Baw4pVS5hnSNko
/Wsp0VnW3q5OK/tPs1pRy+3qWUwwrg5izhYkBfwAAACAf+rC/TDuGcLRc8GzijTqGcXzkc
DW88x3/iKc8gU8cUCXGEukIG7UotrVGNVnicZqv8ZDKFS4KZqSujTfjbgemrseeFO4eQd6
We0p6ESe7wE0JzCacGWJ6PLmV4ceE5jqEsc8cto0yW+K7eEem28I2iPXGv9Yi2r6HENtfG
ZNtOIAAAHYZ8aTg2fGk4MAAAAHc3NoLWRzcwAAAIEAzsJChp5lWfW0Ze2Qp/8EhC1dJ+RC
7KlWRTrQaR5XhDorbL4xAQW0yl9H2fN72jFZyRVcNw0Em4tfdpK75PdPWOodx1TtjCgUXf
bdvX69ulbwmUDsUeH85D7i/j8ePkoahNe9bDs7LhA7dDJMX9edkMawNrz6MJI+35s0R+cY
A00AAAAVAIYb/ljSUclo6TiNwoiF+9byafFJAAAAgFwPkwBgphdmXjWTdOJoMXsk9+CAMN
+zRpiyz/28ovOnSnHc+Ybaj4jlnDZhc6wO2tKPnqxNwfposBJtrFc/nlVnzTgiUGpR1Kka
5NYleeNhS9AQnj4iWvdQWsOKVUuYZ0jZKP1rKdFZ1t6uTiv7T7NaUcvt6llMMK4OYs4WJA
X8AAAAgH/qwv0w7hnC0XPBs4o06hnF85HA1vPMd/4inPIFPHFAlxhLpCBu1KLa1RjVZ4nG
ar/GQyhUuCmakro03424Hpq7HnhTuHkHelntKehEnu8BNCcwmnBliejy5leHHhOY6hLHPH
LaNMlviu3hHptvCNoj1xr/WItq+hxDbXxmTbTiAAAAFE5O2kb+uaE3nWLAMovNC/KYWATe
AAAAAAECAw==
-----END OPENSSH PRIVATE KEY-----"""

# Converted from old format using OpenSSH with `test` as the password.
# $ ssh-keygen -e -p -f OPENSSH_DSA_PRIVATE.key
OPENSSH_V1_ENCRYPTED_DSA_PRIVATE = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCR+DbQqo
2salfbIh0HztjEAAAAEAAAAAEAAAGxAAAAB3NzaC1kc3MAAACBAM7CQoaeZVn1tGXtkKf/
BIQtXSfkQuypVkU60GkeV4Q6K2y+MQEFtMpfR9nze9oxWckVXDcNBJuLX3aSu+T3T1jqHc
dU7YwoFF323b1+vbpW8JlA7FHh/OQ+4v4/Hj5KGoTXvWw7Oy4QO3QyTF/XnZDGsDa8+jCS
Pt+bNEfnGANNAAAAFQCGG/5Y0lHJaOk4jcKIhfvW8mnxSQAAAIBcD5MAYKYXZl41k3TiaD
F7JPfggDDfs0aYss/9vKLzp0px3PmG2o+I5Zw2YXOsDtrSj56sTcH6aLASbaxXP55VZ804
IlBqUdSpGuTWJXnjYUvQEJ4+Ilr3UFrDilVLmGdI2Sj9aynRWdberk4r+0+zWlHL7epZTD
CuDmLOFiQF/AAAAIB/6sL9MO4ZwtFzwbOKNOoZxfORwNbzzHf+IpzyBTxxQJcYS6QgbtSi
2tUY1WeJxmq/xkMoVLgpmpK6NN+NuB6aux54U7h5B3pZ7SnoRJ7vATQnMJpwZYno8uZXhx
4TmOoSxzxy2jTJb4rt4R6bbwjaI9ca/1iLavocQ218Zk204gAAAeBVUr2hdw/PN3S0QUwq
Ny7fOtmBVyuhRDvlS7OTsCaOs4cPF3j9o8K56Fk2Fdj69G8g56/2NrRPHvGyCtoN4olKwZ
Cc/MsePe0R7vWumVgTt1kDk6/CcnAUnTtCL7GW7a1w+8ZDwBotCZgznDD9NlnhfH0g0MZ9
eLP4UY181lYC6452fy8E2pV9qyYufRnRYe5Gu0zoRjEuyYDbNzDBCU4WZ4O7InJDiHuVVE
hocQSVu4WzfABuCageM2wCkbKeM0mRZw1jljhO8a/T45wLmoYQxnUYFeUkUuy4akn5/uJ2
xvIn3zl6fCqiWAnwbRjZeBfQ7q+5E/jUrUklGyBeEMn2RNo9kYTEOItuj6j8bXYELsTyjH
tJ8DplDkNN3/FYG+D8JYyhuaGd4cSLtjXS95nuazHvwyb60CQxPwbmUcojqsrM65Yu7+dQ
wwYEpG5w9/IlKJ62JmEqhEVMI4HHyDLcocYlU6OoD1Ivy09dcIO8uRBYc9jFccj/1ej5oI
tn6RsW0HRlVx06tbp6RDHBfAdg5suu5pW9uv2tESbEqpMHt4FQgqKcSQwzYLvo/bfPuxs0
HNOQMLNwRg8yYbCG+u2HU9YTlQdTgG/5h+eYsQLObPU+TjYgS5p6sUZCkTCnOz8=
-----END OPENSSH PRIVATE KEY-----"""


OPENSSH_DSA_PUBLIC = (
    "ssh-dss AAAAB3NzaC1kc3MAAACBAM7CQoaeZVn1tGXtkKf/BIQtXSfkQuypVkU60GkeV4Q6K"
    "2y+MQEFtMpfR9nze9oxWckVXDcNBJuLX3aSu+T3T1jqHcdU7YwoFF323b1+vbpW8JlA7FHh/O"
    "Q+4v4/Hj5KGoTXvWw7Oy4QO3QyTF/XnZDGsDa8+jCSPt+bNEfnGANNAAAAFQCGG/5Y0lHJaOk"
    "4jcKIhfvW8mnxSQAAAIBcD5MAYKYXZl41k3TiaDF7JPfggDDfs0aYss/9vKLzp0px3PmG2o+I"
    "5Zw2YXOsDtrSj56sTcH6aLASbaxXP55VZ804IlBqUdSpGuTWJXnjYUvQEJ4+Ilr3UFrDilVLm"
    "GdI2Sj9aynRWdberk4r+0+zWlHL7epZTDCuDmLOFiQF/AAAAIB/6sL9MO4ZwtFzwbOKNOoZxf"
    "ORwNbzzHf+IpzyBTxxQJcYS6QgbtSi2tUY1WeJxmq/xkMoVLgpmpK6NN+NuB6aux54U7h5B3p"
    "Z7SnoRJ7vATQnMJpwZYno8uZXhx4TmOoSxzxy2jTJb4rt4R6bbwjaI9ca/1iLavocQ218Zk20"
    "4g=="
)

# Same key as OPENSSH_RSA_PUBLIC, wrapped at 70 characters.
SSHCOM_RSA_PUBLIC = b"""---- BEGIN SSH2 PUBLIC KEY ----
AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTKAPkPAW
zlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk+X6Lc4+lAfp1
YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcjRToF6/jpLw==
---- END SSH2 PUBLIC KEY ----"""

# Same key as OPENSSH_DSA_PUBLIC.
SSHCOM_DSA_PUBLIC = b"""---- BEGIN SSH2 PUBLIC KEY ----
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
SSHCOM_RSA_PRIVATE_NO_PASSWORD = b"""---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
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
SSHCOM_RSA_PRIVATE_WITH_PASSWORD = b"""---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
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
---- END SSH2 ENCRYPTED PRIVATE KEY ----"""

SSHCOM_DSA_PRIVATE_NO_PASSWORD = b"""---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
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
PUTTY_RSA_PRIVATE_NO_PASSWORD = b"""PuTTY-User-Key-File-2: ssh-rsa\r
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
PUTTY_RSA_PRIVATE_WITH_PASSWORD = b"""PuTTY-User-Key-File-2: ssh-rsa\r
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

# Same as PUTTY_RSA_PRIVATE_NO_PASSWORD but in v3 format
# puttygen test-v2.ppk -o test-v3.ppk --reencrypt
PUTTY_V3_RSA_PRIVATE_V3_NO_PASSWORD = b"""PuTTY-User-Key-File-3: ssh-rsa\r
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
Private-MAC: 393d670fe58e8ce89e66f55e22523ec39bfcf8fa908e583b7c53823e142e52d3
"""

# Same as v3
# With password "chevah"
# puttygen test-v2.ppk -o test-v3.ppk  -O private -P --ppk-param kdf=argon2id
PUTTY_V3_RSA_PRIVATE_WITH_PASSWORD = b"""PuTTY-User-Key-File-3: ssh-rsa\r
Encryption: aes256-cbc\r
Comment: imported-openssh-key\r
Public-Lines: 4\r
AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTK\r
APkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk\r
+X6Lc4+lAfp1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcj\r
RToF6/jpLw==\r
Key-Derivation: Argon2id\r
Argon2-Memory: 8192\r
Argon2-Passes: 34\r
Argon2-Parallelism: 1\r
Argon2-Salt: 426aaa1672c0dbf7154b7610f5d45e23\r
Private-Lines: 8\r
AuVHQmNuEXDSMHEigSf7KDUB01HNPzINHhzeBlnRkKcU/sQJxortxwX84L/o/COp\r
GyDfUqZEObBgU7gIFezXLXkay/Qxw1AWuFgswqzXgKGPZ8+6S0D/ZhAcJlOrKGDf\r
yYtqs/8fswauzKahZx8dxFP3sN/pzCzSasLV6bJ/33SN7Q4czjVYoTuCBYb1qm6k\r
0bg+h+CHoIePFGXz3jhLbjSnf405M6MgznD3WMZPLbY+rTtnvroVuLqC0Mu+cdpR\r
30tkdJaHwstYDsB8yKlCYiIXWtRIKYUkBEZFKpWo7woEe2IqSaiiJ9hTghJuQ5ZQ\r
53OjORmnoevIn5eitewY0wwB+FsM+vWJ3PWvSu+DIEAEE1jbzjy2hSUVMvj/2f05\r
Nakw2IT6CC7TCkI8nAzzI48O10DDJ8BFVm3GOqFv1Pzmgh/VePiPRXussZhFpFnm\r
cDe7srHEqLjxnnOZw7KKqg==\r
Private-MAC: 2f56110ed1745e3153a70deb4bb57314b1b14dcf3ebc34d13f1ee47c9222cfc0\r
"""

# Same as v3 but with argon21
# With password "chevah"
# puttygen test-v2.ppk -o test-v3.ppk  -O private -P --ppk-param kdf=argon2i
PUTTY_V3_RSA_PRIVATE_WITH_PASSWORD_ARGON2I = b"""PuTTY-User-Key-File-3: ssh-rsa\r
Encryption: aes256-cbc\r
Comment: imported-openssh-key\r
Public-Lines: 4\r
AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTK\r
APkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk\r
+X6Lc4+lAfp1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcj\r
RToF6/jpLw==\r
Key-Derivation: Argon2i\r
Argon2-Memory: 8192\r
Argon2-Passes: 13\r
Argon2-Parallelism: 1\r
Argon2-Salt: f2efdbaac9f11a994de82a1b9e418874\r
Private-Lines: 8\r
o9870SrOsNN5Nm1WI/TKqpyKgSRyGX0JDGW2a3uO9YCeqxb1AL8vEk2yRRlxkzy4\r
Hvh7xmI2KNnAeuZvkJJjUYHNNTp+KYbV17paU6Cf5GAwOaKJdrwX31zxrPqbYzmi\r
KmpNZLAGhoIEbFY6W5y7E1NnoM4zyZ1vsg6Z1eapTCtlgeOQr7rNkNlpoKjaopiA\r
s7G5h+A+FAeqfh6aaiZf3dswbw5mavcnWTPTnZNbWDziR/blRk/aOanCj4HVoWx+\r
o6dOZnwl9PxY07R9RUk2DNJhr9XiibTTb5ymRk9SVPUjbrV8uC3DLiuejDZ+drgG\r
qotb7VbS0s7+Dbe5ctRyOkr1yx1UQaEMV3OTrqlE6CGuRdfjyQJWidGYFHZTmgUR\r
wm3sW+T90MGCnFEukHxEmXWZJmL3pYO8+dYYRi+RGB9zuO7KskbyLgqm4m023gwT\r
5EpqsPFNUv3iL3kU1HtzVQ==\r
Private-MAC: 90a441b935e29c1e7fd3efb79a330554e0e99d2c15948efded9916afd8ba8626\r
"""

# Same as v3 but with argon21
# With password "chevah"
# puttygen test-v2.ppk -o test-v3.ppk  -O private -P --ppk-param kdf=argon2d
PUTTY_V3_RSA_PRIVATE_WITH_PASSWORD_ARGON2D = b"""PuTTY-User-Key-File-3: ssh-rsa\r
Encryption: aes256-cbc\r
Comment: imported-openssh-key\r
Public-Lines: 4\r
AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTK\r
APkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk\r
+X6Lc4+lAfp1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcj\r
RToF6/jpLw==\r
Key-Derivation: Argon2d\r
Argon2-Memory: 8192\r
Argon2-Passes: 13\r
Argon2-Parallelism: 1\r
Argon2-Salt: f319597cb7bc378717a32b7809b466ef\r
Private-Lines: 8\r
mDtZZwVUvEKw6vgott8cT4rLzGfR6kOOdfhfjXR3KtRjbE32YthmuxtUF040kaLE\r
DubnQ5x+/LnbpycXWeSYsOgYOODC22s+XTqqsgqXHSIqjWZnVswOGfyY2x8VdnSS\r
i6G42BwSxZHU5bNBZkVn4t63USS8cyGIOzhhNebob4jR864JoQy7UpcJCt7dxzRy\r
iOAvFY6M11WJUN1g8lHQaJ0HuDjQEPD2CPw87bMGDayo4I5RvYa617pkKNGZ1AOJ\r
nzYrjkpv1kHBL0AKfA2ZTQKs2g4PGBa2YBK+UolYKACFaiRLX/du+6cW6fDQ7u92\r
kSGZED0rjP+Z6s9376I7E05AnPSFWqlE3XLtxaL1KqkbZ+ffOrRqIpPnYsmeYeIl\r
hYHH406V+VdlGZzNkqfrTH0m7X8Ra39Y48/nhPHmaJLhnVU15RVkoAdazoAEN779\r
WwsJE3IFnF0qDKB6p5wPyw==\r
Private-MAC: 7dd2f4638f52515edf5282d290179b63079f64b2c9bed65cdc1a99c60d710807\r
"""

# This is the same key as OPENSSH_DSA_PRIVATE
PUTTY_DSA_PRIVATE_NO_PASSWORD = b"""PuTTY-User-Key-File-2: ssh-dss\r
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

# Same as PUTTY_DSA_PRIVATE_NO_PASSWORD but in v3 format
# puttygen dsa-v2.ppk -o dsa-v3.ppk --reencrypt
PUTTY_V3_DSA_PRIVATE_NO_PASSWORD_V3 = b"""PuTTY-User-Key-File-3: ssh-dss\r
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
Private-MAC: 9e617cd5bf19f880d3a6a1a0551b699f732e27ec78af65b764de465d82600e18\r
"""

PUTTY_ED25519_PRIVATE_NO_PASSWORD = b"""PuTTY-User-Key-File-2: ssh-ed25519\r
Encryption: none\r
Comment: ed25519-key-20210106\r
Public-Lines: 2\r
AAAAC3NzaC1lZDI1NTE5AAAAIEjwKguKHPrqp3UEqSP7XTmOhBavcTxkHwnzQveQ\r
2MGG\r
Private-Lines: 1\r
AAAAINWl263e/oNph4x7jM94kE7BaSNcXD7G6bbWatylw61A\r
Private-MAC: ead2308fe2f6be87941f17e9d61ede28da2cde8a\r
"""

# Same as PUTTY_ED25519_PRIVATE_NO_PASSWORD but in v3 format.
PUTTY_V3_ED25519_PRIVATE_NO_PASSWORD = b"""PuTTY-User-Key-File-3: ssh-ed25519\r
Encryption: none\r
Comment: ed25519-key-20210106\r
Public-Lines: 2\r
AAAAC3NzaC1lZDI1NTE5AAAAIEjwKguKHPrqp3UEqSP7XTmOhBavcTxkHwnzQveQ\r
2MGG\r
Private-Lines: 1\r
AAAAINWl263e/oNph4x7jM94kE7BaSNcXD7G6bbWatylw61A\r
Private-MAC: b3617706ea98c2476aa733296636d7845a7d62e871a5dd0057d11d74f218d0e1\r
"""

# Password is: chevah
PUTTY_ED25519_PRIVATE_WITH_PASSWORD = b"""PuTTY-User-Key-File-2: ssh-ed25519\r
Encryption: aes256-cbc\r
Comment: ed25519-key-20210106\r
Public-Lines: 2\r
AAAAC3NzaC1lZDI1NTE5AAAAIKY6CzyQPkESUswMjxdbK7XgpfAExYRc0ydzwzco\r
bmlL\r
Private-Lines: 1\r
jvO/yHUJlgjCCzEFlkYwDeSIYggO3Ry1/iP1lm49BU6GljU/miaUemDBHT9umt0o\r
Private-MAC: 6b753f6180f48d153a700c6734b46b2e52f1f7e9\r
"""

PUTTY_ECDSA_SHA2_NISTP256_PRIVATE_NO_PASSWORD = b"""
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256\r
Encryption: none\r
Comment: ecdsa-key-20210106\r
Public-Lines: 3\r
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPA3+gjOpajd\r
9iRVm72ArvQfjVW+3bz9IMrPNMIANSmwTj+0NuFgXZGLaxT8BKslZLZvJX+XuUr/\r
Yvgn32oS7Iw=\r
Private-Lines: 1\r
AAAAIDe7fQUAaorrEkedXTSmXrCY4vabtFV7e4Z8xBSvty8Q\r
Private-MAC: a84b17c5dead6fed8f474406929312d45c096dfc\r
""".strip()

PUTTY_V3_ECDSA_SHA2_NISTP256_PRIVATE_NO_PASSWORD = b"""
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256\r
Encryption: none\r
Comment: ecdsa-key-20210106\r
Public-Lines: 3\r
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPA3+gjOpajd\r
9iRVm72ArvQfjVW+3bz9IMrPNMIANSmwTj+0NuFgXZGLaxT8BKslZLZvJX+XuUr/\r
Yvgn32oS7Iw=\r
Private-Lines: 1\r
AAAAIDe7fQUAaorrEkedXTSmXrCY4vabtFV7e4Z8xBSvty8Q\r
Private-MAC: 6488b1e2221448122e8884df9622350510e7cd266d174b307104a15e5669afb5\r
""".strip()

PUTTY_ECDSA_SHA2_NISTP384_PRIVATE_NO_PASSWORD = b"""
PuTTY-User-Key-File-2: ecdsa-sha2-nistp384\r
Encryption: none\r
Comment: ecdsa-key-20210106\r
Public-Lines: 3\r
AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBEjK280ap/RD\r
R916Q00OI1LIHyRG1fcH6twBjmynTgl0uGlcb8bnbpGO1JOgbhBqqzVQHVckHzqT\r
fUif6rRRQuiUJEenXRmgjQ0uEcj21Rdomz7TJPz1k8tHmOZCHgJx6g==\r
Private-Lines: 2\r
AAAAMQCNcgWtnEeeTqFN383FBJdM90keHkJwproyLPgWQLlbZe+r8py0Pl7mUHvj\r
SGmXUVc=\r
Private-MAC: 1464df777d20427e2b99adb148ed4b8a1a839409\r
""".strip()

PUTTY_V3_ECDSA_SHA2_NISTP384_PRIVATE_NO_PASSWORD = b"""
PuTTY-User-Key-File-3: ecdsa-sha2-nistp384\r
Encryption: none\r
Comment: ecdsa-key-20210106\r
Public-Lines: 3\r
AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBEjK280ap/RD\r
R916Q00OI1LIHyRG1fcH6twBjmynTgl0uGlcb8bnbpGO1JOgbhBqqzVQHVckHzqT\r
fUif6rRRQuiUJEenXRmgjQ0uEcj21Rdomz7TJPz1k8tHmOZCHgJx6g==\r
Private-Lines: 2\r
AAAAMQCNcgWtnEeeTqFN383FBJdM90keHkJwproyLPgWQLlbZe+r8py0Pl7mUHvj\r
SGmXUVc=\r
Private-MAC: 73cdd8880d60561a21bc23017b191471354158e2f343e1b48e8dbe0e46b74067\r
""".strip()

PUTTY_ECDSA_SHA2_NISTP521_PRIVATE_NO_PASSWORD = """PuTTY-User-Key-File-2: ecdsa-sha2-nistp521\r
Encryption: none\r
Comment: ecdsa-key-20210106\r
Public-Lines: 4\r
AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGtj24Kr7OY\r
21mtlHTFuH0NmrhI1mco0nND4FvDbNTTU/87t1ZDqbPEnRqmYBM6/dGPyOK82PH8\r
NmCrCjj0rmckNgC3+Jg/+ok1bJG7/WeTOObnIdDBJklxksIjMF6LG6hVngIibxgF\r
V3iBGD5eWUr40AK+6+wN7uKsaFHMBCg8lde5Mg==\r
Private-Lines: 2\r
AAAAQgE64XtEewBVYUz+sfojvHmsiwdT+2BBBw1IAcKuozuhsz8EkOEOBJGZqCBP\r
B9pAqlHsVHQJF/uVpFbJFUnjEokJ4w==\r
Private-MAC: e828d7207e0e73453005d606216ca36c64d1e304\r
""".strip()

PUTTY_V3_ECDSA_SHA2_NISTP521_PRIVATE_NO_PASSWORD = b"""
PuTTY-User-Key-File-3: ecdsa-sha2-nistp521\r
Encryption: none\r
Comment: ecdsa-key-20210106\r
Public-Lines: 4\r
AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGtj24Kr7OY\r
21mtlHTFuH0NmrhI1mco0nND4FvDbNTTU/87t1ZDqbPEnRqmYBM6/dGPyOK82PH8\r
NmCrCjj0rmckNgC3+Jg/+ok1bJG7/WeTOObnIdDBJklxksIjMF6LG6hVngIibxgF\r
V3iBGD5eWUr40AK+6+wN7uKsaFHMBCg8lde5Mg==\r
Private-Lines: 2\r
AAAAQgE64XtEewBVYUz+sfojvHmsiwdT+2BBBw1IAcKuozuhsz8EkOEOBJGZqCBP\r
B9pAqlHsVHQJF/uVpFbJFUnjEokJ4w==\r
Private-MAC: 3b713999a444c896d6ea7605aba44684693249d6de9b1a0775b60a9bf8e0f19a\r
""".strip()


class DummyOpenContext(object):
    """
    Helper for testing operations using open context manager.

    It keeps a record or all calls in self.calls.
    """

    def __init__(self):
        self.calls = []
        self.last_stream = None

    def __call__(self, path, mode):
        self.last_stream = BytesIO()
        self.calls.append({"path": path, "mode": mode, "stream": self.last_stream})
        return self

    def __enter__(self):
        return self.last_stream

    def __exit__(self, exc_type, exc_value, tb):
        return False


class TestHelpers(ChevahTestCase, CommandLineMixin):
    """
    Unit tests for helper methods from this module.
    """

    def test_path(self):
        """
        Will take an unicode and will return the os encoded path.
        """
        result = _path("path-\N{sun}")
        if self.os_name == "windows":
            self.assertEqual("path-\N{sun}", result)
        else:
            self.assertEqual(b"path-\xe2\x98\x89", result)


class TestKey(ChevahTestCase):
    """
    Unit test for SSH key generation.

    The actual test creating real keys are located in functional.
    """

    def setUp(self):
        super(TestKey, self).setUp()
        self.rsaObj = keys.Key._fromRSAComponents(
            n=keydata.RSAData["n"],
            e=keydata.RSAData["e"],
            d=keydata.RSAData["d"],
            p=keydata.RSAData["p"],
            q=keydata.RSAData["q"],
            u=keydata.RSAData["u"],
        )._keyObject
        self.dsaObj = keys.Key._fromDSAComponents(
            y=keydata.DSAData["y"],
            p=keydata.DSAData["p"],
            q=keydata.DSAData["q"],
            g=keydata.DSAData["g"],
            x=keydata.DSAData["x"],
        )._keyObject
        self.ecObj = keys.Key._fromECComponents(
            x=keydata.ECDatanistp256["x"],
            y=keydata.ECDatanistp256["y"],
            privateValue=keydata.ECDatanistp256["privateValue"],
            curve=keydata.ECDatanistp256["curve"],
        )._keyObject
        self.ecObj384 = keys.Key._fromECComponents(
            x=keydata.ECDatanistp384["x"],
            y=keydata.ECDatanistp384["y"],
            privateValue=keydata.ECDatanistp384["privateValue"],
            curve=keydata.ECDatanistp384["curve"],
        )._keyObject
        self.ecObj521 = keys.Key._fromECComponents(
            x=keydata.ECDatanistp521["x"],
            y=keydata.ECDatanistp521["y"],
            privateValue=keydata.ECDatanistp521["privateValue"],
            curve=keydata.ECDatanistp521["curve"],
        )._keyObject
        self.ed25519Obj = keys.Key._fromEd25519Components(
            a=keydata.Ed25519Data["a"], k=keydata.Ed25519Data["k"]
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
            b"\x00\x00\x00\x07ssh-dss\x00\x00\x00(?\xc7\xeb\x86;\xd5TFA\xb4"
            b"\xdf\x0c\xc4E@4,d\xbc\t\xd9\xae\xdd[\xed-\x82nQ\x8cf\x9b\xe8\xe1"
            b"jrg\x84p<"
        )

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
        self.assertBadKey(content, "Key is too short.")

    def assertKeyParseError(self, content):
        """
        Check that key content fail to parse.
        """
        self.assertBadKey(content, "Fail to parse key content.")

    def _getKeysForFingerprintTest(self):
        """
        Return tuple with public RSA and DSA keys from the test data.
        """
        rsa = keys.Key._fromRSAComponents(
            n=keydata.RSAData["n"],
            e=keydata.RSAData["e"],
            d=keydata.RSAData["d"],
            p=keydata.RSAData["p"],
            q=keydata.RSAData["q"],
            u=keydata.RSAData["u"],
        )._keyObject
        dsa = keys.Key._fromDSAComponents(
            y=keydata.DSAData["y"],
            p=keydata.DSAData["p"],
            q=keydata.DSAData["q"],
            g=keydata.DSAData["g"],
            x=keydata.DSAData["x"],
        )._keyObject
        return (rsa, dsa)

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
            self.assertEqual(privateKey.data()[k], v)

    def test_init(self):
        """
        Test that the PublicKey object is initialized correctly.
        """
        obj = keys.Key._fromRSAComponents(n=int(5), e=int(3))._keyObject
        key = keys.Key(obj)
        self.assertEqual(key._keyObject, obj)

    def test_equal(self):
        """
        Test that Key objects are compared correctly.
        """
        rsa1 = keys.Key(self.rsaObj)
        rsa2 = keys.Key(self.rsaObj)
        rsa3 = keys.Key(keys.Key._fromRSAComponents(n=int(5), e=int(3))._keyObject)
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
        rsa3 = keys.Key(keys.Key._fromRSAComponents(n=int(5), e=int(3))._keyObject)
        dsa = keys.Key(self.dsaObj)
        self.assertFalse(rsa1 != rsa2)
        self.assertTrue(rsa1 != rsa3)
        self.assertTrue(rsa1 != dsa)
        self.assertTrue(rsa1 is not object)
        self.assertTrue(rsa1 is not None)

    def test_type(self):
        """
        Test that the type method returns the correct type for an object.
        """
        self.assertEqual(keys.Key(self.rsaObj).type(), "RSA")
        self.assertEqual(keys.Key(self.rsaObj).sshType(), b"ssh-rsa")
        self.assertEqual(keys.Key(self.dsaObj).type(), "DSA")
        self.assertEqual(keys.Key(self.dsaObj).sshType(), b"ssh-dss")
        self.assertRaises(RuntimeError, keys.Key(None).type)
        self.assertRaises(RuntimeError, keys.Key(None).sshType)
        self.assertRaises(RuntimeError, keys.Key(self).type)
        self.assertRaises(RuntimeError, keys.Key(self).sshType)

    def test_generate_no_key_type(self):
        """
        An error is raised when generating a key with unknown type.
        """
        with self.assertRaises(KeyCertException) as context:
            Key.generate(key_type=None)

        self.assertEqual('Unknown key type "not-specified".', context.exception.message)

    def test_generate_unknown_type(self):
        """
        An error is raised when generating a key with unknown type.
        """
        with self.assertRaises(KeyCertException) as context:
            Key.generate(key_type="bad-type")

        self.assertEqual('Unknown key type "bad-type".', context.exception.message)

    @attr("slow")
    def test_generate_rsa(self):
        """
        Check generation of an RSA key with a case insensitive type name.
        """
        key = Key.generate(key_type="rSA", key_size=1024)

        self.assertEqual("RSA", key.type())
        self.assertEqual(1024, key.size())

    @attr("slow")
    def test_generate_dsa(self):
        """
        Check generation of a DSA key with a case insensitive type name.
        """
        key = Key.generate(key_type="dSA", key_size=1024)

        self.assertEqual("DSA", key.type())
        self.assertEqual(1024, key.size())

    def test_generate_failed(self):
        """
        A ServerError is raised when it fails to generate the key.
        """
        with self.assertRaises(KeyCertException) as context:
            Key.generate(key_type="dSa", key_size=512)

        self.assertEqual(
            'Wrong key size "512". ' "Key size must be 1024, 2048, 3072, or 4096 bits.",
            context.exception.message,
        )

    def test_guessStringType_unknown(self):
        """
        None is returned when could not detect key type.
        """
        content = mk.bytes()

        result = Key._guessStringType(content)

        self.assertIsNone(result)

    def test_guessStringType_X509_PEM_certificate(self):
        """
        PEM certificates are recognized as public keys.
        """
        content = (
            b"-----BEGIN CERTIFICATE-----\n" b"CONTENT\n" b"-----END CERTIFICATE-----\n"
        )

        result = Key._guessStringType(content)

        self.assertEqual("public_x509_certificate", result)

    def test_guessStringType_X509_PUBLIC(self):
        """
        x509 public PEM are recognized as public keys.
        """
        content = (
            b"-----BEGIN PUBLIC KEY-----\n" b"CONTENT\n" b"-----END PUBLIC KEY-----\n"
        )

        result = Key._guessStringType(content)

        self.assertEqual("public_x509", result)

    def test_guessStringType_PKCS8_PRIVATE(self):
        """
        PKS#8 private PEM are recognized as private keys.
        """
        content = (
            b"-----BEGIN PRIVATE KEY-----\n" b"CONTENT\n" b"-----END PRIVATE KEY-----\n"
        )

        result = Key._guessStringType(content)

        self.assertEqual("private_pkcs8", result)

    def test_guessStringType_PKCS8_PRIVATE_ENCRYPTED(self):
        """
        PKS#8 encrypted private PEM are recognized as private keys.
        """
        content = (
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            b"CONTENT\n"
            b"-----END ENCRYPTED PRIVATE KEY-----\n"
        )

        result = Key._guessStringType(content)

        self.assertEqual("private_encrypted_pkcs8", result)

    def test_guessStringType_private_OpenSSH_RSA(self):
        """
        Can recognize an OpenSSH RSA private key.
        """
        result = Key._guessStringType(OPENSSH_RSA_PRIVATE)

        self.assertEqual("private_openssh", result)

    def test_guessStringType_private_OpenSSH_DSA(self):
        """
        Can recognize an OpenSSH DSA private key.
        """
        result = Key._guessStringType(OPENSSH_DSA_PRIVATE)

        self.assertEqual("private_openssh", result)

    def test_guessStringType_public_OpenSSH(self):
        """
        Can recognize an OpenSSH public key.
        """
        result = Key._guessStringType(OPENSSH_RSA_PUBLIC)

        self.assertEqual("public_openssh", result)

    def test_guessStringType_public_PKCS1(self):
        """
        Can recognize an PKCS1 PEM public key.
        """
        result = Key._guessStringType(PKCS1_RSA_PUBLIC)

        self.assertEqual("public_pkcs1_rsa", result)

    def test_guessStringType_private_SSHCOM(self):
        """
        Can recognize an SSH.com private key.
        """
        result = Key._guessStringType(SSHCOM_RSA_PRIVATE_NO_PASSWORD)

        self.assertEqual("private_sshcom", result)

    def test_guessStringType_public_SSHCOM(self):
        """
        Can recognize an SSH.com public key.
        """
        result = Key._guessStringType(SSHCOM_RSA_PUBLIC)

        self.assertEqual("public_sshcom", result)

    def test_guessStringType_putty(self):
        """
        Can recognize a Putty private key.
        """
        result = Key._guessStringType(PUTTY_RSA_PRIVATE_NO_PASSWORD)

        self.assertEqual("private_putty", result)

    def test_getKeyFormat_unknown(self):
        """
        Inform using a human readable text that format is not known.
        """
        result = Key.getKeyFormat(b"no-such-format")

        self.assertEqual("Unknown format", result)

    def test_getKeyFormat_known(self):
        """
        Return the human readable description of key format.
        """

        result = Key.getKeyFormat(SSHCOM_RSA_PUBLIC)

        self.assertEqual("SSH.com Public", result)

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
        self.assertEqual(result.data()["e"], sut.data()["e"])
        self.assertEqual(result.data()["n"], sut.data()["n"])

    def test_fromFile(self):
        """
        Test that fromFile works correctly.
        """
        self.test_segments = mk.fs.createFileInTemp(content=keydata.privateRSA_openssh)
        key_path = mk.fs.getRealPathFromSegments(self.test_segments)

        self.assertEqual(
            keys.Key.fromFile(key_path), keys.Key.fromString(keydata.privateRSA_openssh)
        )

        self.assertRaises(keys.BadKeyError, keys.Key.fromFile, key_path, "bad_type")

    def test_fromString_type_unkwown(self):
        """
        An exceptions is raised when reading a key for which type could not
        be detected. Exception only contains the beginning of the content.
        """
        content = "some-value-" * 100

        self.assertBadKey(
            content,
            "Cannot guess the type for \"b'some-value-"
            "some-value-some-value-some-value-some-value-some-"
            "value-some-value-som'\"",
        )

    def test_fromString_struct_errors(self):
        """
        Errors caused by parsing the content are raises as BadKeyError.
        """
        content = OPENSSH_DSA_PUBLIC[:32]

        self.assertKeyParseError(content)

    def test_fromString_errors(self):
        """
        keys.Key.fromString should raise BadKeyError when the key is invalid.
        """
        self.assertRaises(keys.BadKeyError, keys.Key.fromString, "")
        # no key data with a bad key type
        self.assertRaises(keys.BadKeyError, keys.Key.fromString, "", "bad_type")
        # trying to decrypt a key which doesn't support encryption
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
            keydata.publicRSA_lsh,
            passphrase=b"unencrypted",
        )
        # trying t  fo decrypt a key with the wrong passphrase
        self.assertRaises(
            keys.EncryptedKeyError,
            keys.Key.fromString,
            keys.Key(self.rsaObj).toString("openssh", b"encrypted"),
        )
        # key with no key data
        self.assertRaises(
            keys.BadKeyError, keys.Key.fromString, "-----BEGIN RSA KEY-----\nwA==\n"
        )
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
-----END RSA PRIVATE KEY-----""",
            passphrase=b"encrypted",
        )
        # key with invalid encryption type
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
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
-----END RSA PRIVATE KEY-----""",
            passphrase=b"encrypted",
        )
        # key with bad IV (AES)
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
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
-----END RSA PRIVATE KEY-----""",
            passphrase=b"encrypted",
        )
        # key with bad IV (DES3)
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
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
-----END RSA PRIVATE KEY-----""",
            passphrase=b"encrypted",
        )

    def test_toStringErrors(self):
        """
        Test that toString raises errors appropriately.
        """
        self.assertRaises(keys.BadKeyError, keys.Key(self.rsaObj).toString, "bad_type")

    def test_fromString_BLOB_blob_type_non_ascii(self):
        """
        Raise with printable information for the bad type,
        even if blob type has non-ascii data.
        """
        badBlob = common.NS("ssh-\xbd\xbd\xbd")
        self.assertBadKey(
            badBlob,
            "Cannot guess the type for "
            "\"b'\\x00\\x00\\x00\\nssh-\\xc2\\xbd\\xc2\\xbd\\xc2\\xbd'\"",
        )

    def test_blobRSA(self):
        """
        Return the over-the-wire SSH format of the RSA public key.
        """
        self.assertEqual(
            keys.Key(self.rsaObj).blob(),
            common.NS(b"ssh-rsa")
            + common.MP(self.rsaObj.private_numbers().public_numbers.e)
            + common.MP(self.rsaObj.private_numbers().public_numbers.n),
        )

    def test_blobDSA(self):
        """
        Return the over-the-wire SSH format of the DSA public key.
        """
        publicNumbers = self.dsaObj.private_numbers().public_numbers

        self.assertEqual(
            keys.Key(self.dsaObj).blob(),
            common.NS(b"ssh-dss")
            + common.MP(publicNumbers.parameter_numbers.p)
            + common.MP(publicNumbers.parameter_numbers.q)
            + common.MP(publicNumbers.parameter_numbers.g)
            + common.MP(publicNumbers.y),
        )

    def test_blobEC(self):
        """
        Return the over-the-wire SSH format of the EC public key.
        """
        from cryptography import utils

        byteLength = (self.ecObj.curve.key_size + 7) // 8
        self.assertEqual(
            keys.Key(self.ecObj).blob(),
            common.NS(keydata.ECDatanistp256["curve"])
            + common.NS(keydata.ECDatanistp256["curve"][-8:])
            + common.NS(
                b"\x04"
                + utils.int_to_bytes(
                    self.ecObj.private_numbers().public_numbers.x, byteLength
                )
                + utils.int_to_bytes(
                    self.ecObj.private_numbers().public_numbers.y, byteLength
                )
            ),
        )

    def test_blobEd25519(self):
        """
        Return the over-the-wire SSH format of the Ed25519 public key.
        """
        from cryptography.hazmat.primitives import serialization

        publicBytes = self.ed25519Obj.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        self.assertEqual(
            keys.Key(self.ed25519Obj).blob(),
            common.NS(b"ssh-ed25519") + common.NS(publicBytes),
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
        numbers = self.rsaObj.private_numbers()
        self.assertEqual(
            keys.Key(self.rsaObj).privateBlob(),
            common.NS(b"ssh-rsa")
            + common.MP(numbers.public_numbers.n)
            + common.MP(numbers.public_numbers.e)
            + common.MP(numbers.d)
            + common.MP(numbers.iqmp)
            + common.MP(numbers.p)
            + common.MP(numbers.q),
        )

    def test_privateBlobDSA(self):
        """
        L{keys.Key.privateBlob} returns the SSH protocol-level format of a DSA
        private key.
        """
        publicNumbers = self.dsaObj.private_numbers().public_numbers

        self.assertEqual(
            keys.Key(self.dsaObj).privateBlob(),
            common.NS(b"ssh-dss")
            + common.MP(publicNumbers.parameter_numbers.p)
            + common.MP(publicNumbers.parameter_numbers.q)
            + common.MP(publicNumbers.parameter_numbers.g)
            + common.MP(publicNumbers.y)
            + common.MP(self.dsaObj.private_numbers().x),
        )

    def test_privateBlobEC(self):
        """
        L{keys.Key.privateBlob} returns the SSH ptotocol-level format of EC
        private key.
        """
        from cryptography.hazmat.primitives import serialization

        self.assertEqual(
            keys.Key(self.ecObj).privateBlob(),
            common.NS(keydata.ECDatanistp256["curve"])
            + common.NS(keydata.ECDatanistp256["curve"][-8:])
            + common.NS(
                self.ecObj.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
            )
            + common.MP(self.ecObj.private_numbers().private_value),
        )

    def test_privateBlobEd25519(self):
        """
        L{keys.Key.privateBlob} returns the SSH protocol-level format of an
        Ed25519 private key.
        """
        from cryptography.hazmat.primitives import serialization

        publicBytes = self.ed25519Obj.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        privateBytes = self.ed25519Obj.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

        self.assertEqual(
            keys.Key(self.ed25519Obj).privateBlob(),
            common.NS(b"ssh-ed25519")
            + common.NS(publicBytes)
            + common.NS(privateBytes + publicBytes),
        )

    def test_privateBlobNoKeyObject(self):
        """
        Raises L{RuntimeError} if the underlying key object does not exists.
        """
        badKey = keys.Key(None)

        self.assertRaises(RuntimeError, badKey.privateBlob)

    def test_fromString_PUBLIC_OPENSSH_RSA(self):
        """
        Can load public RSA OpenSSH key.
        """
        sut = Key.fromString(OPENSSH_RSA_PUBLIC)

        self.checkParsedRSAPublic1024(sut)

    def test_fromString_PUBLIC_PKC1_RSA(self):
        """
        Can load public RSA PKC1 key.
        """
        sut = Key.fromString(PKCS1_RSA_PUBLIC)

        self.checkParsedRSAPublic1024(sut)

    def test_fromString_PUBLIC_OPENSSH_RSA_too_short(self):
        """
        An exception is raised when public RSA OpenSSH key is bad formatted.
        """
        self.assertKeyIsTooShort("ssh-rsa")

    def test_fromString_PUBLIC_OPENSSH_invalid_payload(self):
        """
        Raise an exception when key blob has a bad format.
        """
        self.assertKeyParseError("ssh-rsa AAAAB3NzaC1yc2EA")

    def test_fromString_PUBLIC_OPENSSH_DSA(self):
        """
        Can load a public OpenSSH in DSA format.
        """
        sut = Key.fromString(OPENSSH_DSA_PUBLIC)

        self.checkParsedDSAPublic1024(sut)

    def test_fromString_OpenSSH_public(self):
        """
        It can load an OpenSSH public key.
        """
        sut = Key.fromString(OPENSSH_RSA_PUBLIC)

        self.checkParsedRSAPublic1024(sut)

    def test_fromString_OpenSSH_private_missing_password(self):
        """
        It fails to load an ecrypted key when password is not provided.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            keys.Key.fromString(keydata.privateRSA_openssh_encrypted)

        self.assertEqual(
            "Passphrase must be provided for an encrypted key",
            context.exception.message,
        )

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
        self.assertEqual(
            keys.Key.fromString(privateDSAData),
            keys.Key.fromString(privateDSAData + "\n"),
        )

    def test_fromString_PRIVATE_OPENSSH_newer(self):
        """
        Newer versions of OpenSSH generate encrypted keys which have a longer
        IV than the older versions. These newer keys are also loaded.
        """
        key = keys.Key.fromString(
            keydata.privateRSA_openssh_encrypted_aes, passphrase=b"testxp"
        )
        self.assertEqual(key.type(), "RSA")
        key2 = keys.Key.fromString(
            keydata.privateRSA_openssh_encrypted_aes + b"\n", passphrase=b"testxp"
        )
        self.assertEqual(key, key2)

    def test_toString_OPENSSH_rsa(self):
        """
        Test that the Key object generates OpenSSH keys correctly.
        """
        key = Key.fromString(OPENSSH_V1_RSA_PRIVATE)

        result = key.public().toString("openssh")
        self.assertEqual(OPENSSH_RSA_PUBLIC, result)

        result = key.toString("openssh")
        self.assertEqual(OPENSSH_RSA_PRIVATE, result)

    def test_toString_OPENSSH_v1_rsa(self):
        """
        Test that the Key object generates OpenSSH keys correctly.
        """
        key = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = key.public().toString("openssh_v1")
        self.assertEqual(OPENSSH_RSA_PUBLIC, result)

        result = key.toString("openssh_v1")
        self.assertStartsWith(
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n" b"b3BlbnNzaC1rZXk", result
        )
        reloaded = Key.fromString(result)
        self.assertEqual(reloaded, key)

    def addSSHCOMKeyHeaders(self, source, headers):
        """
        Add headers to a SSH.com key.

        Long headers are wrapped at 70 characters.
        """
        lines = source.splitlines()
        for key, value in headers.items():
            line = "{}: {}".format(key, value)
            header = "\\\n".join(textwrap.wrap(line, 70))
            lines.insert(1, header.encode("utf-8"))
        return b"\n".join(lines)

    def checkParsedDSAPublic1024(self, sut):
        """
        Check the default public DSA key of size 1024.

        This is a shared test for parsing DSA key from various formats.
        """
        self.assertEqual(1024, sut.size())
        self.assertEqual("DSA", sut.type())
        self.assertTrue(sut.isPublic())
        self.checkParsedDSAPublic1024Data(sut)

    def checkParsedDSAPublic1024Data(self, sut):
        """
        Check the public part values for the default DSA key of size 1024.
        """
        data = sut.data()
        self.assertEqual(
            int(
                "89826398702575694025672739759021185748719093895775418981133245507"
                "56542191015877768589699407493932539140865803919573940821357868468"
                "55675657634384222748339103943127442354510383477300256462657784441"
                "71019786268219332779725063911288445634960873466719023048095246499"
                "763675183656402590703132265805882271082319033570"
            ),
            data["y"],
        )
        self.assertEqual(
            int(
                "14519098631088118929874535941241101897542246758347965800832728196"
                "81139199597265476885338795620826004398884602230901691384070382776"
                "92982149652731866793940314712388781003443391479314606037340161379"
                "86631331044475413634865132557582890274917465191550388575486379853"
                "0603422003777150811982254140040687593424378397517"
            ),
            data["p"],
        )
        self.assertEqual(
            int("765629040155792319453907037659138573169171493193"), data["q"]
        )
        self.assertEqual(
            int(
                "64647318098084998690447943642968245369499209364165550549740815561"
                "71156388976417089337555666453157891497405105710031098879473402131"
                "15408225147127626829407642540707192214402604495716677723330515779"
                "34611656548484464881147166978432509157365635746874869548636130785"
                "946819310836368885242376237240564866586977240572"
            ),
            data["g"],
        )

    def checkParsedDSAPrivate1024(self, sut):
        """
        Check the default private DSA key of size 1024.
        """
        self.assertEqual(1024, sut.size())
        self.assertEqual("DSA", sut.type())
        self.assertFalse(sut.isPublic())
        data = sut.data()
        self.checkParsedDSAPublic1024Data(sut)
        self.assertEqual(
            int("447059752886431435417087644871194130561824720094"), data["x"]
        )

    def checkParseED25519Private(self, sut):
        """
        Check the default private ED key.
        """
        self.assertEqual(256, sut.size())
        self.assertEqual("Ed25519", sut.type())
        self.assertEqual(b"ssh-ed25519", sut.sshType())
        self.assertFalse(sut.isPublic())
        data = sut.data()
        self.assertEqual(
            b"H\xf0*\x0b\x8a\x1c\xfa\xea\xa7u\x04\xa9#"
            b"\xfb]9\x8e\x84\x16\xafq<d\x1f\t\xf3B\xf7\x90\xd8\xc1\x86",
            data["a"],
        )
        self.assertEqual(
            b"\xd5\xa5\xdb\xad\xde\xfe\x83i\x87\x8c{\x8c"
            b"\xcfx\x90N\xc1i#\\\\>\xc6\xe9\xb6\xd6j\xdc\xa5\xc3\xad@",
            data["k"],
        )

    def checkParseECDSA256Private(self, sut):
        """
        Check the default private ECDSA key of size 256.
        """
        self.assertEqual(256, sut.size())
        self.assertEqual("EC", sut.type())
        self.assertEqual(b"ecdsa-sha2-nistp256", sut.sshType())
        self.assertFalse(sut.isPublic())
        data = sut.data()
        self.assertEqual(
            int(
                "108653985922575495831455438688025548017135775794055889135985"
                "150468304120654256"
            ),
            data["x"],
        )
        self.assertEqual(
            int(
                "3539295734849026692713678957269176284433037397838158425727137"
                "8201444091096204"
            ),
            data["y"],
        )
        self.assertEqual(
            int(
                "252084699263301204901777793191881954449812697988584991308139"
                "15648781475852048"
            ),
            data["privateValue"],
        )
        self.assertEqual("ecdsa-sha2-nistp256", data["curve"])

    def checkParseECDSA384Private(self, sut):
        """
        Check the default private ECDSA key of size 384.
        """
        self.assertEqual(384, sut.size())
        self.assertEqual("EC", sut.type())
        self.assertEqual(b"ecdsa-sha2-nistp384", sut.sshType())
        self.assertFalse(sut.isPublic())
        data = sut.data()
        self.assertEqual(
            int(
                "1120377828922608503816705989895402195704724469432815819813909"
                "3563493784434074664770757552630188877039345451446332075"
            ),
            data["x"],
        )
        self.assertEqual(
            int(
                "820561365460938594173613421894075233970023220702364300455709"
                "9067975115514374468669516341218754297628118025144267242"
            ),
            data["y"],
        )
        self.assertEqual(
            int(
                "217704394275079527449821219041780952018954068994705805522096"
                "48672017052607392742400750553189721892676300516837773655"
            ),
            data["privateValue"],
        )
        self.assertEqual("ecdsa-sha2-nistp384", data["curve"])

    def checkParseECDSA521Private(self, sut):
        """
        Check the default private ECDSA key of size 384.
        """
        self.assertEqual(521, sut.size())
        self.assertEqual("EC", sut.type())
        self.assertEqual(b"ecdsa-sha2-nistp521", sut.sshType())
        self.assertFalse(sut.isPublic())
        data = sut.data()
        self.assertEqual(
            int(
                "575946163275684216572287655819753290168045735639065337167146"
                "2757410336252172929914930328513418153583025932019025257555921"
                "977303915549355871374495357809927222"
            ),
            data["x"],
        )
        self.assertEqual(
            int(
                "2466648813452073098641976930882615172021518938344202222286332"
                "6007817176633618054662362944525041064939804805715990911995870"
                "75381269720405103254588443613182258"
            ),
            data["y"],
        )
        self.assertEqual(
            int(
                "4221861115108077704182122958166381218745996746275086003675630"
                "8531396812933733891747966663579986273453584268921082684125610"
                "37807083546341161456593999982299619"
            ),
            data["privateValue"],
        )
        self.assertEqual("ecdsa-sha2-nistp521", data["curve"])

    def checkParsedRSAPublic1024(self, sut):
        """
        Check the default public RSA key of size 1024.
        """
        self.assertEqual(1024, sut.size())
        self.assertEqual("RSA", sut.type())
        self.assertTrue(sut.isPublic())
        self.checkParsedRSAPublic1024Data(sut)

    def checkParsedRSAPublic1024Data(self, sut):
        """
        Check data for public RSA key of size 1024.
        """
        data = sut.data()
        self.assertEqual(65537, data["e"])
        self.assertEqual(
            int(
                "12955309129371696361961156024018278506192853914566590418922947244"
                "33008028380639675460754206681134187533029942882729688747039044313"
                "67411245192523108247958392655021595783971049572916657240822239036"
                "02442387266290082476044614892594356080524766995335587624348179950"
                "6405887692619349988915280409504938876523941259567"
            ),
            data["n"],
        )

    def checkParsedRSAPrivate1024(self, sut):
        """
        Check the default private RSA key of size 1024.
        """
        self.assertEqual(1024, sut.size())
        self.assertEqual("RSA", sut.type())
        self.assertEqual(b"ssh-rsa", sut.sshType())
        self.assertEqual(
            "fc:39:4c:d4:51:c8:5d:78:1e:4d:9d:1e:73:42:52:55", sut.fingerprint()
        )
        self.assertIsFalse(sut.isPublic())
        data = sut.data()
        self.assertEqual(65537, data["e"])
        self.checkParsedRSAPublic1024Data(sut)
        self.assertEqual(
            int(
                "57010713839675255669157840568333483699071044890077432241594488384"
                "64981848192265169337649163172545274951948296799964023904757013291"
                "17313931268194522463817291948793747715146018146051093951466872189"
                "64147610108577761761364098616952641696814228146724216997423652825"
                "24517268536277980834876649127946895862158846465"
            ),
            data["d"],
        )
        self.assertEqual(
            int(
                "10661640454627350493191065484215149934251067848734449698668476614"
                "18981319570111200535213963399376281314470995958266981264747210946"
                "6364885923117389812635119"
            ),
            data["q"],
        )
        self.assertEqual(
            int(
                "12151328104249520956550929707892880056509323657595783040548358917"
                "98785549316902458371621691657702435263762556929800891556172971312"
                "6473919204485168003686593"
            ),
            data["p"],
        )
        self.assertEqual(
            int(
                "48025268260110814473325498559726067155427614012608550802573547885"
                "48894562354231797601376827466469492368471033644629931755771678685"
                "474342157953188378164913"
            ),
            data["u"],
        )

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
                "Comment": '"short comment"',
                "Subject": "Very very long subject" * 10,
                "x-private": mk.string(),
            },
        )
        sut = Key.fromString(key_content)

        self.assertEqual(1024, sut.size())
        self.assertEqual("RSA", sut.type())
        self.assertTrue(sut.isPublic())
        data = sut.data()
        self.assertEqual(65537, data["e"])

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
        content = "---- BEGIN SSH2 PUBLIC KEY ----"

        self.assertBadKey(content, "Fail to find END tag for SSH.com key.")

        content = "---- BEGIN SSH2 PUBLIC KEY ----\nnext line"

        self.assertBadKey(content, "Fail to find END tag for SSH.com key.")

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

        result = sut.toString(type="sshcom")

        self.assertEqual(SSHCOM_RSA_PUBLIC, result)

    def test_toString_SSHCOM_RSA_public_with_comment(self):
        """
        Can export a public RSA SSH.com key with headers.
        """
        sut = Key.fromString(OPENSSH_RSA_PUBLIC)
        comment = mk.string() * 20

        result = sut.toString(type="sshcom", extra=comment)

        expected = self.addSSHCOMKeyHeaders(
            source=SSHCOM_RSA_PUBLIC,
            headers={"Comment": '"%s"' % comment},
        )
        self.assertEqual(expected, result)

    def test_toString_SSHCOM_DSA_public(self):
        """
        Can export a public DSA SSH.com key.
        """
        sut = Key.fromString(OPENSSH_DSA_PUBLIC)

        result = sut.toString(type="sshcom")

        self.assertEqual(SSHCOM_DSA_PUBLIC, result)

    def test_fromString_PRIVATE_OPENSSH_RSA(self):
        """
        Can load a private OpenSSH RSA key.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_OPENSSH_v1_RSA(self):
        """
        Can load a private OpenSSH v1 RSA key.
        """
        sut = Key.fromString(OPENSSH_V1_RSA_PRIVATE)

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_OPENSSH_DSA(self):
        """
        Can load a private OpenSSH DSA key.
        """
        sut = Key.fromString(OPENSSH_DSA_PRIVATE)

        self.checkParsedDSAPrivate1024(sut)

    def test_fromString_PRIVATE_OPENSSH_v1_DSA(self):
        """
        Can load a private OpenSSH V1 DSA key.
        """
        sut = Key.fromString(OPENSSH_V1_DSA_PRIVATE)

        self.checkParsedDSAPrivate1024(sut)

    def test_fromString_PRIVATE_OPENSSH_short(self):
        """
        Raise an error when private OpenSSH key is too short.
        """
        content = "-----BEGIN RSA PRIVATE KEY-----"

        self.assertKeyIsTooShort(content)

        content = "-----BEGIN RSA PRIVATE KEY-----\nAnother Line"

        self.assertBadKey(
            content, "Failed to decode key (Bad Passphrase?): " "EndOfStreamError()"
        )

    def test_fromString_PRIVATE_OPENSSH_bad_encoding(self):
        """
        Raise an error when private OpenSSH key data can not be decoded.
        """
        content = "-----BEGIN RSA PRIVATE KEY-----\nAnother Line\nLast"

        self.assertKeyParseError(content)

    def test_fromString_PRIVATE_SSHCOM_unencrypted_with_passphrase(self):
        """
        When loading a unencrypted SSH.com private key with passhphrase
        will raise BadKeyError.
        """

        with self.assertRaises(BadKeyError) as context:
            Key.fromString(SSHCOM_RSA_PRIVATE_NO_PASSWORD, passphrase=b"pass")

        self.assertEqual("SSH.com key not encrypted", context.exception.message)

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
        sut = Key.fromString(SSHCOM_RSA_PRIVATE_WITH_PASSWORD, passphrase=b"chevah")

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
        content = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"

        self.assertKeyParseError(content)

        content = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nnext line"

        self.assertKeyParseError(content)

    def test_fromString_PRIVATE_SSHCOM_RSA_encrypted_no_password(self):
        """
        An exceptions is raised whey trying to load a private SSH.com key
        which is encrypted, but without providing a password.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(SSHCOM_RSA_PRIVATE_WITH_PASSWORD)

        self.assertEqual(
            "Passphrase must be provided for an encrypted key.",
            context.exception.message,
        )

    def test_fromString_PRIVATE_SSHCOM_RSA_with_wrong_password(self):
        """
        An exceptions is raised whey trying to load a private SSH.com key
        which is encrypted, but providing a wrong password.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(SSHCOM_RSA_PRIVATE_WITH_PASSWORD, passphrase=b"on")

        self.assertEqual("Bad password or bad key format.", context.exception.message)

    def test_fromString_PRIVATE_OPENSSH_bad_magic(self):
        """
        Exception is raised when key data does not start with the key marker.
        """
        content = """---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
B2/56wAAAi4AAAA3
---- END SSH2 ENCRYPTED PRIVATE KEY ----"""

        self.assertBadKey(content, "Fail to parse key content.")

    def test_fromString_PRIVATE_OPENSSH_bad_key_type(self):
        """
        Exception is raised when key has an unknown type.
        """
        content = """---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
P2/56wAAAi4AAAA3aWYtbW9kbntzaW==
---- END SSH2 ENCRYPTED PRIVATE KEY ----"""

        self.assertBadKey(content, 'Unknown SSH.com key type "if-modn{si"')

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
            "Failed to load certificate. \"[('asn1 encoding routines'",
            context.exception.message,
        )

    def test_fromString_X509_PEM_EC(self):
        """
        EC public key from an X509 PEM certificate are supported.
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
        result = Key.fromString(data)

        self.assertEqual("EC", result.type())
        self.assertEqual(b"ecdsa-sha2-nistp192", result.sshType())
        self.assertEqual(192, result.size())

    def test_fromString_PKCS1_PUBLIC_ECDSA(self):
        """
        It can extract ECDSA 192 public key from an PKCS1 public EC PEM file.
        """
        # This is the same as the X509 RSA cert.
        # $ openssl x509 -in bla.cert -pubkey -noout
        data = b"""-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEc6VKUjy6I6MqLmB+x4UhVeutcFCq
0Vai8iZQW9XFlPH+MC2bBpF8pmaQDwpcLvCe
-----END PUBLIC KEY-----
"""
        result = Key.fromString(data)

        self.assertEqual("EC", result.type())
        self.assertEqual(b"ecdsa-sha2-nistp192", result.sshType())

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
        self.assertEqual("RSA", sut.type())
        self.assertEqual(1024, sut.size())

        components = sut.data()
        self.assertEqual(65537, components["e"])
        n = int(
            "14510135000543456324610075074919561379239940215773254633039625814"
            "50191438083097108908667737243399472490927083264564327600896049375"
            "92092816317169486450111458914839337717035721053431064458247582292"
            "33425907841901335798792724220900289242783534069221630733833594745"
            "1002424312049140771718167143894887320401855011989"
        )
        self.assertEqual(n, components["n"])

    def test_fromString_PKCS1_PUBLIC_PEM_invalid_format(self):
        """
        It fails to load invalid formated PKCS1 public PEM file.
        """
        data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOoZUYd8KMYbre5zZIwR+V6dO2
O1u6TvSz6Of7rB5clQIDAQAB
-----END PUBLIC KEY-----
"""
        with self.assertRaises(BadKeyError) as context:
            Key.fromString(data)

        self.assertStartsWith(
            "Failed to load PKCS#1 public key. \"[('DECODER routines'",
            context.exception.message,
        )

    def test_fromString_PKCS1_PUBLIC_RSA(self):
        """
        It can extract RSA public key from an PKCS1 public RSA PEM file.
        """
        # This is the same as the X509 RSA cert.
        # $ openssl x509 -in bla.cert -pubkey -noout
        data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOoZUYd8KMYbre5zZIwR+V6dO2
+cCYVS46BHbRbqt7gczkoIWhKWqXi9PzOEacPQDY8rpRsu68CSPTHveWhudwa4zG
wSpNamh7jV2tzyY3IFZj3pcD3G85OVpeBOe3SzfnoeEX/0MovRwXbaw39fTswZgb
O1u6TvSz6Of7rB5clQIDAQAB
-----END PUBLIC KEY-----
"""

        sut = Key.fromString(data)

        self.assertTrue(sut.isPublic())
        self.assertEqual("RSA", sut.type())
        self.assertEqual(1024, sut.size())

        components = sut.data()
        self.assertEqual(65537, components["e"])
        n = int(
            "14510135000543456324610075074919561379239940215773254633039625814"
            "50191438083097108908667737243399472490927083264564327600896049375"
            "92092816317169486450111458914839337717035721053431064458247582292"
            "33425907841901335798792724220900289242783534069221630733833594745"
            "1002424312049140771718167143894887320401855011989"
        )
        self.assertEqual(n, components["n"])

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
        self.assertEqual("DSA", sut.type())
        self.assertEqual(1024, sut.size())

        components = sut.data()
        y = int(
            "33608096932577498834618892325416552088960771123656082234885710486"
            "75507586904443594643612585160476637613084634099891307779753871384"
            "19072984388914093315900417736990449366567905225558889080164633948"
            "75642330307431599331123161679260711587324602448450132263105327567"
            "324900691359269978674482129301723462636106625693"
        )
        p = int(
            "17914554197956231476032656039682646299975055883332311875135017227"
            "52180243454588892360869849018970437236700881503241838175380166833"
            "56570852141623851276212449051705325396966909384918507908491159872"
            "81118556760058432354600693107636249903432532125207156471720334839"
            "5401646777661899361981163845950810903143363602443"
        )
        g = int(
            "12935985053463672691492638315705405640647316377002915690069266627"
            "73032720642846501430445126372712764104983906841935717997673558164"
            "74657088881395785073303554687569602926262408886111665706815822813"
            "14448994749901282518897434324098506093655990924057550618491224583"
            "7106339202519842112263186663472095769544164572498"
        )
        self.assertEqual(y, components["y"])
        self.assertEqual(p, components["p"])
        self.assertEqual(g, components["g"])
        self.assertEqual(
            732130160578857514768194964362219084190055012723, components["q"]
        )

    def test_fromString_PCKS1_PUBLIC_DSA(self):
        """
        It can extract RSA public key from an PKCS1 public DSA PEM file.
        """
        # This is the same as the X509 DSA cert.
        # $ openssl x509 -in bla.cert -pubkey -noout
        data = """-----BEGIN PUBLIC KEY-----
MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP8cmay2TI42sOHaJJp+xGrEDNEbh0hR
rvQ92wSB8xgHH3k2TW+HAYXIRDILLfTlvaaAsb36eQWRouIPlSegFuY7U0KCBeVI
2h7d7OpqSvzSBXp0LBszhPsHuVzdLQSHk4nYXkMp7DNPrlDJGueR8QIWW+Mmql7L
CF+5y+Cdp2gLAhUAgD3aEZFRtfjU/zMKpEEAyIQKGXMCgYEAuDbsOEtOEeEkdZ0V
faBlhOY0yO/9nuYcIB1rz+6o1eMDP3uMj3DooJJggLuqLKXSXAa5buQao0K2exnL
EpZDNPIeg4272B8CYDFlsjdO4Tj19hkn/SbSZfI+kKDRUh4UlVxLqUDZbnVQPUmu
8KtRvUzVKA1b5X9UfDoznh76/VIDgYQAAoGAL9wJalml5uGIROFkt356h1H28Ke0
HywjOsDQlEKaLi3y8E7Es0BlATtZ09ZdkkDt3jf7oHj/8Nkf4Y63oSjEvI/Fyoz4
Yepr32ITAi5MoIgbq5wO2/MxKDC9hUW6B9hqgm+7Q6Rz7p6U3LCmT23ccsfmnZBu
k9c9iA5IfqqbMp0=
-----END PUBLIC KEY-----
"""

        sut = Key.fromString(data)

        self.assertTrue(sut.isPublic())
        self.assertEqual("DSA", sut.type())
        self.assertEqual(1024, sut.size())

        components = sut.data()
        y = int(
            "33608096932577498834618892325416552088960771123656082234885710486"
            "75507586904443594643612585160476637613084634099891307779753871384"
            "19072984388914093315900417736990449366567905225558889080164633948"
            "75642330307431599331123161679260711587324602448450132263105327567"
            "324900691359269978674482129301723462636106625693"
        )
        p = int(
            "17914554197956231476032656039682646299975055883332311875135017227"
            "52180243454588892360869849018970437236700881503241838175380166833"
            "56570852141623851276212449051705325396966909384918507908491159872"
            "81118556760058432354600693107636249903432532125207156471720334839"
            "5401646777661899361981163845950810903143363602443"
        )
        g = int(
            "12935985053463672691492638315705405640647316377002915690069266627"
            "73032720642846501430445126372712764104983906841935717997673558164"
            "74657088881395785073303554687569602926262408886111665706815822813"
            "14448994749901282518897434324098506093655990924057550618491224583"
            "7106339202519842112263186663472095769544164572498"
        )
        self.assertEqual(y, components["y"])
        self.assertEqual(p, components["p"])
        self.assertEqual(g, components["g"])
        self.assertEqual(
            732130160578857514768194964362219084190055012723, components["q"]
        )

    def test_fromString_PRIVATE_PKCS8_invalid_format(self):
        """
        It fails to load invalid formated PKCS8 PEM file.
        """
        data = """-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAM6hlRh3woxhut7n
r3fAiJ9U0aDLrcUh
-----END PRIVATE KEY-----
"""
        with self.assertRaises(BadKeyError) as context:
            Key.fromString(data)

        self.assertStartsWith(
            "Failed to load PKCS#8 PEM. \"[('DECODER routines'",
            context.exception.message,
        )

    def test_fromString_PRIVATE_PKCS8_RSA(self):
        """
        It can extract RSA key from an PKCS8 private RSA PEM file,
        without encryption.
        """
        # openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs1.key
        data = """-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALh9Xq1JqQNIHpmi
/KAux/WIL0/e0kd49MoA+Q8BbOW7kFEdyYC7S5OOfsaGunFuONYzANU3Q7HPDu14
jQ4QhWSmeVzIzovmYaT5fotzj6UB+nVjEJH2j34VcxZIk/faNHAj7guFZjGdhSV2
8A7ksPP1B5HTIqKbByNFOgXr+OkvAgMBAAECgYAIHlxAO/GYF2BhWm7LjcN25ptO
ZHvUcVo0WX6cTm/AXFSpfSoU5CkbQTYK/nrN6w/NPUlYGKp99KKviJKMf+WeyRmc
z0nXF+megnkdPNwYdoFhUUQRdLp86zJZPXmhjspvqtEFOdZXQiez/TkeGnfyv9FH
87imgH7c3BAkOX/qAQJBAOgCdF0L7lLKOtnUlBRZSRqmJgciEWrqRa0abeRYmfQj
EIG0WEa+ohYnBkgCN/q1MoxSTpuMb2nsml61dSxOIMECQQDLkQNTYXjZebq29DMz
xsCCrt3b/HaIdG46QNRvVsrdjAHJOKGX0Euq91GFHGmXbURypakH9HMAVsZr7rQb
+JXvAkAFLPjXkoqQgj5p2ZosEgnVdFto0VO+JNfFEs/cxjU5Awc9PX6ypVIMWHaF
aLdC+oPUKYnjYnCh1ktjTXz9rgiBAkA6wKDIGPLLOcH0+egpQmzfit7HlkcTvR7v
OzTU6aTlano9fFXPPjQIpRbnJzsmlEfUGxH9FMV4TJM6JYvgItALAkB/gEX15UvF
FD0Dgyb0iS3iUXyKLqdrifF20TM/ynYs/20uodhShs1qfEH7syyLh/eBjK4p04ad
YeoPZTgdwt0x
-----END PRIVATE KEY-----
"""
        sut = Key.fromString(data)

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PKCS8_RSA_ENCRYPTED(self):
        """
        It can extract RSA key from an PKCS8 private RSA PEM file,
        with encryption.
        """
        # openssl pkcs8 -topk8 -inform PEM -outform PEM -in pkcs1.key
        data = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQICxbcEPe+vjECAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAhBDpmQH4bpzIQSQqpw+GjBIIC
gMKX1CcvdGi6ZFxbhp9ycCnXU04bCsQrijAyYmndInf+EWSSTWpIzM86K6huOjdG
fKsTrmWb0bUM7LTu50GzNHwwGJgVMrUrL7rZQcTkht1D3mdLXWpanaCWyn2IYW8s
jXuzftEUn4AVHVzMeU95wlorgH33QlcAIDt/ZIDzeCfygsu3yJQW44kzWvp3/Eoy
tjBL+K6u7IRoHj67knh6YJ6cQxusK9cAFEpS8RfRLJpryAZyUfvwJteVK0LXQgcS
b8WsIwC+iv8E2QKExFmh4aoUsSsfOrdAb/H2iKTNU/qChCkeeYtzPFVLNmXYL1zG
9G80EGEKmaMgPTIt+oXx2cmY4W21jRGEQ/5KAUcLAWNR+3fEcDVdgfKxlCWQGSad
fQdemXnYhXW1emyb6RvWl0ml7f3ZzVFdeWgShLwx9ZVYdMT/ed4aCucK++XaXl55
dK37TVTeVe6dzyhOADj8lNZ695Xt7+QO+O/hd+9K54xrjmt9TUKxFBbmS3Oqz9rI
T/0h4ym65OOio0CCePzj0vNrCvAD5rBo63B9Kjqxwnyzh2XmIBhUxcCzBEzm1pbS
FM6UHBQ3Jj595U0LGgParXRXxmt1A0i28Q9JhOQp5R1lxD+/q4q3eq/kV05bACyD
IdZR03u3euOWDtw0+Q6+DXvq53m1X1d9A4Dl14spNZoAdGnDLawrvdbWPvSeeXqR
5O9OYI0dake/SYROPlDvc2MgehllwSVU1IXdsrP3xChP2V4YupESRDcFcX+/zlph
HZ6BMxEKcYuIT9PKwhhp+FrwNo6J8mylpQLnCJ3hvXlhEPmyalg4rwVoeTHXRK6Y
TbW5RErmC8ifa/J4NdCv7MY=
-----END ENCRYPTED PRIVATE KEY-----
"""
        sut = Key.fromString(data, passphrase=b"password")

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PKCS8_ENCRYPTED_no_pass(self):
        """
        It fails to extract RSA key from an PKCS8 private RSA PEM file,
        if no password is provided and file is encrypted.
        """
        # openssl pkcs8 -topk8 -inform PEM -outform PEM -in pkcs1.key
        data = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQICxbcEPe+vjECAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAhBDpmQH4bpzIQSQqpw+GjBIIC
gMKX1CcvdGi6ZFxbhp9ycCnXU04bCsQrijAyYmndInf+EWSSTWpIzM86K6huOjdG
fKsTrmWb0bUM7LTu50GzNHwwGJgVMrUrL7rZQcTkht1D3mdLXWpanaCWyn2IYW8s
jXuzftEUn4AVHVzMeU95wlorgH33QlcAIDt/ZIDzeCfygsu3yJQW44kzWvp3/Eoy
tjBL+K6u7IRoHj67knh6YJ6cQxusK9cAFEpS8RfRLJpryAZyUfvwJteVK0LXQgcS
b8WsIwC+iv8E2QKExFmh4aoUsSsfOrdAb/H2iKTNU/qChCkeeYtzPFVLNmXYL1zG
9G80EGEKmaMgPTIt+oXx2cmY4W21jRGEQ/5KAUcLAWNR+3fEcDVdgfKxlCWQGSad
fQdemXnYhXW1emyb6RvWl0ml7f3ZzVFdeWgShLwx9ZVYdMT/ed4aCucK++XaXl55
dK37TVTeVe6dzyhOADj8lNZ695Xt7+QO+O/hd+9K54xrjmt9TUKxFBbmS3Oqz9rI
T/0h4ym65OOio0CCePzj0vNrCvAD5rBo63B9Kjqxwnyzh2XmIBhUxcCzBEzm1pbS
FM6UHBQ3Jj595U0LGgParXRXxmt1A0i28Q9JhOQp5R1lxD+/q4q3eq/kV05bACyD
IdZR03u3euOWDtw0+Q6+DXvq53m1X1d9A4Dl14spNZoAdGnDLawrvdbWPvSeeXqR
5O9OYI0dake/SYROPlDvc2MgehllwSVU1IXdsrP3xChP2V4YupESRDcFcX+/zlph
HZ6BMxEKcYuIT9PKwhhp+FrwNo6J8mylpQLnCJ3hvXlhEPmyalg4rwVoeTHXRK6Y
TbW5RErmC8ifa/J4NdCv7MY=
-----END ENCRYPTED PRIVATE KEY-----
"""
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(data)

        self.assertEqual(
            "Passphrase must be provided for an encrypted key",
            context.exception.message,
        )

    def test_fromString_PRIVATE_PKCS8_DSA(self):
        """
        It can extract DSA key from an PKCS8 private RSA PEM file,
        without encryption.
        """
        # Obtain from a P12
        # openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs1.key
        data = """-----BEGIN PRIVATE KEY-----
MIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBAM7CQoaeZVn1tGXtkKf/BIQtXSfk
QuypVkU60GkeV4Q6K2y+MQEFtMpfR9nze9oxWckVXDcNBJuLX3aSu+T3T1jqHcdU
7YwoFF323b1+vbpW8JlA7FHh/OQ+4v4/Hj5KGoTXvWw7Oy4QO3QyTF/XnZDGsDa8
+jCSPt+bNEfnGANNAhUAhhv+WNJRyWjpOI3CiIX71vJp8UkCgYBcD5MAYKYXZl41
k3TiaDF7JPfggDDfs0aYss/9vKLzp0px3PmG2o+I5Zw2YXOsDtrSj56sTcH6aLAS
baxXP55VZ804IlBqUdSpGuTWJXnjYUvQEJ4+Ilr3UFrDilVLmGdI2Sj9aynRWdbe
rk4r+0+zWlHL7epZTDCuDmLOFiQF/AQWAhROTtpG/rmhN51iwDKLzQvymFgE3g==
-----END PRIVATE KEY-----
"""
        sut = Key.fromString(data)

        self.checkParsedDSAPrivate1024(sut)

    def test_fromString_PRIVATE_PKCS8_EC(self):
        """
        It cat  extract the EC key from an PKCS8 private EC PEM file,
        """
        # openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
        # openssl pkcs8 -topk8 -in private.ec.key -nocrypt
        data = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrNfvVhrhJeyufkeZ
4oQ6i/kUFKudRU+xZ69FaAsw3MehRANCAASpL4fmdxdxbt317O8gV4Op5fVYwDnQ
7C/wsAsbx6monIz1qc1jje9RgggJL5pZ5HfbDInclQfV5T9rz6kWFEZS
-----END PRIVATE KEY-----
"""
        result = Key.fromString(data)

        self.assertEqual("EC", result.type())
        self.assertEqual(b"ecdsa-sha2-nistp256", result.sshType())

    def test_toString_SSHCOM_RSA_private_without_encryption(self):
        """
        Can export a private RSA SSH.com without without encryption.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type="sshcom")

        # Check that it looks like SSH.com private key.
        self.assertStartsWith(
            b"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n"
            b"P2/56wAAAi4AAAA3aWYtbW9kbntzaWdue3JzYS1wa2NzMS1zaGExfSxlbmNyeXB0",
            result,
        )

        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_SSHCOM_RSA_private_encrypted(self):
        """
        Can export an encrypted private RSA SSH.com.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type="sshcom", extra="chevah")

        # Check that it looks like SSH.com private key.
        self.assertStartsWith(
            b"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n"
            b"P2/56wAAAjMAAAA3aWYtbW9kbntzaWdue3",
            result,
        )

        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result, passphrase=b"chevah")
        self.assertEqual(sut, reloaded)

    def test_toString_SSHCOM_DSA_private(self):
        """
        Can export a private DSA SSH.com key.
        """
        sut = Key.fromString(OPENSSH_DSA_PRIVATE)

        result = sut.toString(type="sshcom")

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

    def test_fromString_PRIVATE_PUTTY_not_encrypted_with_passphrase(self):
        """
        When loading a unencrypted PuTTY private key with passhphrase
        will raise BadKeyError.
        """
        with self.assertRaises(BadKeyError) as context:
            Key.fromString(PUTTY_RSA_PRIVATE_NO_PASSWORD, passphrase=b"pass")

        self.assertEqual("PuTTY key not encrypted", context.exception.message)

    def test_fromString_PRIVATE_PUTTY_RSA_with_password(self):
        """
        It can read private RSA keys in Putty format which are encrypted.
        """
        sut = Key.fromString(PUTTY_RSA_PRIVATE_WITH_PASSWORD, passphrase=b"chevah")

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_short(self):
        """
        An exception is raised when key is too short.
        """
        content = "PuTTY-User-Key-File-2: ssh-rsa"

        self.assertKeyIsTooShort(content)

        content = "PuTTY-User-Key-File-2: ssh-rsa\n" "Encryption: aes256-cbc\n"

        self.assertKeyIsTooShort(content)

        content = (
            "PuTTY-User-Key-File-2: ssh-rsa\n"
            "Encryption: aes256-cbc\n"
            "Comment: bla\n"
        )

        self.assertKeyIsTooShort(content)

    def test_fromString_PRIVATE_PUTTY_RSA_bad_password(self):
        """
        An exception is raised when password is not valid.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(PUTTY_RSA_PRIVATE_WITH_PASSWORD, passphrase=b"bad-pass")

        self.assertEqual("Bad password or HMAC mismatch.", context.exception.message)

    def test_fromString_PRIVATE_PUTTY_RSA_missing_password(self):
        """
        An exception is raised when key is encrypted but no password was
        provided.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(PUTTY_RSA_PRIVATE_WITH_PASSWORD)

        self.assertEqual(
            "Passphrase must be provided for an encrypted key.",
            context.exception.message,
        )

    def test_fromString_PRIVATE_PUTTY_unsupported_type(self):
        """
        An exception is raised when key contain a type which is not supported.
        """
        content = """PuTTY-User-Key-File-2: ssh-bad
IGNORED
"""
        self.assertBadKey(content, 'Unsupported key type: "ssh-bad"')

    def test_fromString_PRIVATE_PUTTY_unsupported_encryption(self):
        """
        An exception is raised when key contain an encryption method
        which is not supported.
        """
        content = """PuTTY-User-Key-File-2: ssh-dss
Encryption: aes126-cbc
IGNORED
"""
        self.assertBadKey(content, 'Unsupported encryption type: "aes126-cbc"')

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
            ('Mismatch key type. Header has "ssh-rsa",' ' public has "ssh-dss"'),
        )

    def test_fromString_PRIVATE_PUTTY_hmac_mismatch(self):
        """
        An exception is raised when key HMAC differs from the one
        advertise by the key file.
        """
        content = PUTTY_RSA_PRIVATE_NO_PASSWORD[:-1]
        content += b"a"

        self.assertBadKey(
            content,
            "HMAC mismatch: file declare "
            '"7630b86be300c6302ce1390fb264487bb61e67ca", actual is '
            '"7630b86be300c6302ce1390fb264487bb61e67ce"',
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

        result = sut.toString(type="putty")

        # We can not check the exact text as comment is hardcoded in
        # Twisted.
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_v3_RSA_plain(self):
        """
        Can export to private RSA Putty v3 without encryption.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type="putty_v3")
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_RSA_encrypted(self):
        """
        Can export to encrypted private RSA Putty key.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type="putty", extra="write-pass")

        # We can not check the exact text as comment is hardcoded in
        # Twisted.
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result, passphrase="write-pass")
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_v3_RSA_encrypted(self):
        """
        Can export to encrypted private RSA Putty key v3.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE)

        result = sut.toString(type="putty_v3", extra="write-pass")

        reloaded = Key.fromString(result, passphrase="write-pass")
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_DSA_plain(self):
        """
        Can export to private DSA Putty key without encryption.
        """
        sut = Key.fromString(OPENSSH_DSA_PRIVATE)

        result = sut.toString(type="putty")

        # We can not check the exact text as comment is hardcoded in
        # Twisted.
        # Load the serialized key and see that we get the same key.
        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_v3_DSA_plain(self):
        """
        Can export to private DSA Putty key in v3 format without encryption.
        """
        sut = Key.fromString(OPENSSH_DSA_PRIVATE)

        result = sut.toString(type="putty_v3")

        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_v3_ed25519_plain(self):
        """
        Can export to private ed25519 Putty key in v3 format without encryption.
        """
        sut = Key.fromString(PUTTY_ED25519_PRIVATE_NO_PASSWORD)

        result = sut.toString(type="putty_v3")

        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_v3_ecdsa256_plain(self):
        """
        Can export to private ecdsa 256 Putty key in v3 format without encryption.
        """
        sut = Key.fromString(PUTTY_ECDSA_SHA2_NISTP256_PRIVATE_NO_PASSWORD)

        result = sut.toString(type="putty_v3")

        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_v3_ecdsa384_plain(self):
        """
        Can export to private ecdsa 384 Putty key in v3 format without encryption.
        """
        sut = Key.fromString(PUTTY_ECDSA_SHA2_NISTP384_PRIVATE_NO_PASSWORD)

        result = sut.toString(type="putty_v3")

        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_v3_ecdsa521_plain(self):
        """
        Can export to private ecdsa 384 Putty key in v3 format without encryption.
        """
        sut = Key.fromString(PUTTY_ECDSA_SHA2_NISTP521_PRIVATE_NO_PASSWORD)

        result = sut.toString(type="putty_v3")

        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_PUTTY_public(self):
        """
        Can export to public RSA Putty.
        """
        sut = Key.fromString(OPENSSH_RSA_PRIVATE).public()

        result = sut.toString(type="putty")

        reloaded = Key.fromString(result)
        self.assertEqual(sut, reloaded)

    def test_toString_AGENTV3(self):
        """
        Test that the Key object generates Agent v3 keys correctly.
        """
        key = keys.Key.fromString(keydata.privateRSA_openssh)
        self.assertEqual(key.toString("agentv3"), keydata.privateRSA_agentv3)
        key = keys.Key.fromString(keydata.privateDSA_openssh)
        self.assertEqual(key.toString("agentv3"), keydata.privateDSA_agentv3)

    def test_fromString_AGENTV3(self):
        """
        Test that keys are correctly generated from Agent v3 strings.
        """
        self._testPrivateFromString(keydata.privateRSA_agentv3, "RSA", keydata.RSAData)
        self._testPrivateFromString(keydata.privateDSA_agentv3, "DSA", keydata.DSAData)
        self.assertRaises(
            keys.BadKeyError,
            keys.Key.fromString,
            "\x00\x00\x00\x07ssh-foo" + "\x00\x00\x00\x01\x01" * 5,
        )

    def test_fingerprint(self):
        """
        Will return the md5 fingerprint with colons separator.
        """
        key = keys.Key.fromString(keydata.privateRSA_openssh)

        result = key.fingerprint()
        self.assertEqual(keydata.privateRSA_fingerprint_md5, result)

    def test_fingerprintdefault(self):
        """
        Test that the fingerprint method returns fingerprint in
        L{FingerprintFormats.MD5-HEX} format by default.
        """
        rsaObj, dsaObj = self._getKeysForFingerprintTest()

        self.assertEqual(
            keys.Key(rsaObj).fingerprint(),
            "85:25:04:32:58:55:96:9f:57:ee:fb:a8:1a:ea:69:da",
        )
        self.assertEqual(
            keys.Key(dsaObj).fingerprint(),
            "63:15:b3:0e:e6:4f:50:de:91:48:3d:01:6b:b3:13:c1",
        )

    def test_fingerprint_md5_hex(self):
        """
        fingerprint method generates key fingerprint in
        L{FingerprintFormats.MD5-HEX} format if explicitly specified.
        """
        rsaObj, dsaObj = self._getKeysForFingerprintTest()

        self.assertEqual(
            keys.Key(rsaObj).fingerprint(keys.FingerprintFormats.MD5_HEX),
            "85:25:04:32:58:55:96:9f:57:ee:fb:a8:1a:ea:69:da",
        )
        self.assertEqual(
            keys.Key(dsaObj).fingerprint(keys.FingerprintFormats.MD5_HEX),
            "63:15:b3:0e:e6:4f:50:de:91:48:3d:01:6b:b3:13:c1",
        )

    def test_fingerprintsha256(self):
        """
        fingerprint method generates key fingerprint in
        L{FingerprintFormats.SHA256-BASE64} format if explicitly specified.
        """
        rsaObj, dsaObj = self._getKeysForFingerprintTest()

        self.assertEqual(
            keys.Key(rsaObj).fingerprint(keys.FingerprintFormats.SHA256_BASE64),
            "FBTCOoknq0mHy+kpfnY9tDdcAJuWtCpuQMaV3EsvbUI=",
        )
        self.assertEqual(
            keys.Key(dsaObj).fingerprint(keys.FingerprintFormats.SHA256_BASE64),
            "Wz5o2YbKyxOEcJn1au/UaALSVruUzfz0vaLI1xiIGyY=",
        )

    def test_fingerprintsha1(self):
        """
        fingerprint method generates key fingerprint in
        L{FingerprintFormats.SHA1-BASE64} format if explicitly specified.
        """
        rsaObj, dsaObj = self._getKeysForFingerprintTest()

        self.assertEqual(
            keys.Key(rsaObj).fingerprint(keys.FingerprintFormats.SHA1_BASE64),
            "tuUFlgv3kknie9WYExgS7OQj54k=",
        )
        self.assertEqual(
            keys.Key(dsaObj).fingerprint(keys.FingerprintFormats.SHA1_BASE64),
            "9CCuTybG5aORtuW4jrFcp0PbK4U=",
        )

    def test_fingerprintBadFormat(self):
        """
        A C{BadFingerPrintFormat} error is raised when unsupported
        formats are requested.
        """
        rsaObj = self._getKeysForFingerprintTest()[0]

        with self.assertRaises(keys.BadFingerPrintFormat) as em:
            keys.Key(rsaObj).fingerprint("sha256-base")
        self.assertEqual(
            "Unsupported fingerprint format: sha256-base", em.exception.args[0]
        )

    def test_sign_rsa(self):
        """
        Test that the Key object generates correct signatures.
        """
        key = keys.Key.fromString(keydata.privateRSA_openssh)
        signature = key.sign(b"")
        self.assertTrue(key.verify(signature, b""))
        self.assertEqual(signature, self.rsaSignature)

    def test_verify(self):
        """
        Test that the Key object correctly verifies signatures.
        """
        key = keys.Key.fromString(keydata.publicRSA_openssh)
        self.assertTrue(key.verify(self.rsaSignature, b""))
        self.assertFalse(key.verify(self.rsaSignature, b"a"))
        self.assertFalse(key.verify(self.dsaSignature, b""))
        key = keys.Key.fromString(keydata.publicDSA_openssh)
        self.assertTrue(key.verify(self.dsaSignature, b""))
        self.assertFalse(key.verify(self.dsaSignature, b"a"))
        self.assertFalse(key.verify(self.rsaSignature, b""))

    def test_verifyDSANoPrefix(self):
        """
        Some commercial SSH servers send DSA keys as 2 20-byte numbers;
        they are still verified as valid keys.
        """
        key = keys.Key.fromString(keydata.publicDSA_openssh)
        self.assertTrue(key.verify(self.dsaSignature[-40:], b""))

    def test_repr_rsa(self):
        """
        It can repr a RSA private and public key..
        """
        sut = keys.Key.fromString(OPENSSH_RSA_PRIVATE)
        result = repr(sut)

        self.assertContains(
            "<RSA Private Key (1024 bits)\n" "attr d:\n" "\t08:1e", result
        )
        self.assertContains("attr e:\n" "\t01:00:01\n", result)
        self.assertContains("attr n:\n" "\t00:b8:7d:", result)
        self.assertContains("attr p:\n" "\t00:e8:02:", result)
        self.assertContains("attr q:\n" "\t00:cb:91:", result)
        self.assertContains("attr u:\n" "\t5b:b2:43:", result)
        result = repr(sut.public())

        self.assertContains(
            "<RSA Public Key (1024 bits)\n" "attr e:\n" "\t01:00", result
        )
        self.assertContains("attr n:\n" "\t00:b8:7d:", result)
        self.assertNotContains("attr d:", result)

    def test_repr_dsa(self):
        """
        It can repr a DSA private and public key..
        """
        sut = keys.Key.fromString(OPENSSH_DSA_PRIVATE)
        result = repr(sut)

        self.assertContains(
            "<DSA Private Key (1024 bits)\n" "attr g:\n" "\t5c:0f:93:", result
        )
        self.assertContains("attr p:\n" "\t00:ce:c2:", result)
        self.assertContains("attr q:\n" "\t00:86:1b:", result)
        self.assertContains("attr x:\n" "\t4e:4e:da:", result)
        self.assertContains("attr y:\n" "\t7f:ea:c2:", result)
        result = repr(sut.public())

        self.assertContains(
            "<DSA Public Key (1024 bits)\n" "attr g:\n" "\t5c:0f:93:", result
        )
        self.assertNotContains("attr x:", result)

    def test_repr_ecdsa(self):
        """
        It can repr a ECDSA private and public key..
        """
        sut = keys.Key.fromString(PUTTY_ECDSA_SHA2_NISTP256_PRIVATE_NO_PASSWORD)
        result = repr(sut)

        self.assertContains(
            "<Elliptic Curve Private Key (256 bits)\n"
            "curve:\n"
            "\tecdsa-sha2-nistp256\n"
            "privateValue:\n"
            "\t2520",
            result,
        )
        result = repr(sut.public())

        self.assertContains(
            "Elliptic Curve Public Key (256 bits)\n"
            "curve:\n"
            "\tecdsa-sha2-nistp256\n"
            "x:\n"
            "\t1086",
            result,
        )
        self.assertNotContains("2520846992633", result)

    def test_repr_ed25519(self):
        """
        It can repr a ed25519 private and public key.
        """
        sut = keys.Key.fromString(PUTTY_ED25519_PRIVATE_NO_PASSWORD)
        result = repr(sut)

        self.assertContains(
            "Ed25519 Private Key (256 bits)\n" "attr a:\n" "\t48:f0:2a", result
        )
        self.assertContains("attr k:\n" "\td5:a5:d", result)
        result = repr(sut.public())

        self.assertContains(
            "<Ed25519 Public Key (256 bits)\n" "attr a:\n" "\t48:f0:", result
        )
        self.assertNotContains("attr k:", result)

    def test_fromString_PRIVATE_PUTTY_V3_short(self):
        """
        An exception is raised when key is too short.
        """
        content = "PuTTY-User-Key-File-3: ssh-rsa"

        self.assertKeyIsTooShort(content)

        content = "PuTTY-User-Key-File-3: ssh-rsa\n" "Encryption: aes256-cbc\n"

        self.assertKeyIsTooShort(content)

        content = (
            "PuTTY-User-Key-File-3: ssh-rsa\n"
            "Encryption: aes256-cbc\n"
            "Comment: bla\n"
        )

        self.assertKeyIsTooShort(content)

    def test_fromString_PRIVATE_PUTTY_V3_RSA_bad_password(self):
        """
        An exception is raised when password is not valid.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(PUTTY_V3_RSA_PRIVATE_WITH_PASSWORD, passphrase=b"bad-pass")

        self.assertEqual("Bad password or HMAC mismatch.", context.exception.message)

    def test_fromString_PRIVATE_PUTTY_V3_RSA_missing_password(self):
        """
        An exception is raised when key is encrypted but no password was
        provided.
        """
        with self.assertRaises(EncryptedKeyError) as context:
            Key.fromString(PUTTY_V3_RSA_PRIVATE_WITH_PASSWORD)

        self.assertEqual(
            "Passphrase must be provided for an encrypted key.",
            context.exception.message,
        )

    def test_fromString_PRIVATE_PUTTY_V3_unsupported_type(self):
        """
        An exception is raised when key contain a type which is not supported.
        """
        content = """PuTTY-User-Key-File-3: ssh-bad
IGNORED
"""
        self.assertBadKey(content, 'Unsupported key type: "ssh-bad"')

    def test_fromString_PRIVATE_PUTTY_V3_unsupported_encryption(self):
        """
        An exception is raised when key contain an encryption method
        which is not supported.
        """
        content = """PuTTY-User-Key-File-3: ssh-dss
Encryption: aes126-cbc
IGNORED
"""
        self.assertBadKey(content, 'Unsupported encryption type: "aes126-cbc"')

    def test_fromString_PRIVATE_PUTTY_v3_type_mismatch(self):
        """
        An exception is raised when key header advertise one key type while
        the public key another.
        """
        content = """PuTTY-User-Key-File-3: ssh-rsa
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
            ('Mismatch key type. Header has "ssh-rsa",' ' public has "ssh-dss"'),
        )

    def test_fromString_PRIVATE_PUTTY_v3_RSA_no_encryption(self):
        """
        It can load a Putty v3 RSA private key that has no encryption.
        """
        sut = Key.fromString(PUTTY_V3_RSA_PRIVATE_V3_NO_PASSWORD)

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_v3_RSA_argon2id(self):
        """
        It can load a Putty v3 RSA private key that has encryption
        with argon2id
        """
        sut = Key.fromString(PUTTY_V3_RSA_PRIVATE_WITH_PASSWORD, passphrase="chevah")

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_v3_RSA_argon2i(self):
        """
        It can load a Putty v3 RSA private key that has encryption
        with argon2i
        """
        sut = Key.fromString(
            PUTTY_V3_RSA_PRIVATE_WITH_PASSWORD_ARGON2I, passphrase="chevah"
        )

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_v3_RSA_argon2d(self):
        """
        It can load a Putty v3 RSA private key that has encryption
        with argon2d.
        """
        sut = Key.fromString(
            PUTTY_V3_RSA_PRIVATE_WITH_PASSWORD_ARGON2D, passphrase="chevah"
        )

        self.checkParsedRSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_v3_DSA(self):
        """
        It can load a Putty v3 DSA private key that no encryption.
        """
        sut = Key.fromString(PUTTY_V3_DSA_PRIVATE_NO_PASSWORD_V3)

        self.checkParsedDSAPrivate1024(sut)

    def test_fromString_PRIVATE_PUTTY_v3_ed25519(self):
        """
        It can load a Putty v3 ed25519 private key that no encryption.
        """
        sut = Key.fromString(PUTTY_V3_ED25519_PRIVATE_NO_PASSWORD)

        self.checkParseED25519Private(sut)

    def test_fromString_PRIVATE_PUTTY_v3_ecdsa_256(self):
        """
        It can load a Putty v3 ecdsa private key that no encryption.
        """
        sut = Key.fromString(PUTTY_V3_ECDSA_SHA2_NISTP256_PRIVATE_NO_PASSWORD)

        self.checkParseECDSA256Private(sut)

    def test_fromString_PRIVATE_PUTTY_v3_ecdsa_384(self):
        """
        It can load a Putty v3 ecdsa private key that no encryption.
        """
        sut = Key.fromString(PUTTY_V3_ECDSA_SHA2_NISTP384_PRIVATE_NO_PASSWORD)

        self.checkParseECDSA384Private(sut)

    def test_fromString_PRIVATE_PUTTY_v3_ecdsa_521(self):
        """
        It can load a Putty v3 ecdsa private key that no encryption.
        """
        sut = Key.fromString(PUTTY_V3_ECDSA_SHA2_NISTP521_PRIVATE_NO_PASSWORD)

        self.checkParseECDSA521Private(sut)


class Test_generate_ssh_key_parser(ChevahTestCase, CommandLineMixin):
    """
    Unit tests for generate_ssh_key_parser.
    """

    def setUp(self):
        super(Test_generate_ssh_key_parser, self).setUp()
        self.parser = ArgumentParser(prog="test-command")
        self.subparser = self.parser.add_subparsers(
            help="Available sub-commands", dest="sub_command"
        )

    def test_default(self):
        """
        It only need a subparser and sub-command name.
        """
        generate_ssh_key_parser(self.subparser, "key-gen")

        options = self.parseArguments(["key-gen"])

        self.assertNamespaceEqual(
            {
                "sub_command": "key-gen",
                "key_comment": None,
                "key_file": None,
                "key_password": None,
                "key_size": None,
                "key_type": "rsa",
                "key_format": "openssh_v1",
                "key_skip": False,
            },
            options,
        )

    def test_value(self):
        """
        Options are parsed from the command line.
        """
        generate_ssh_key_parser(self.subparser, "key-gen")

        options = self.parseArguments(
            [
                "key-gen",
                "--key-comment",
                "some comment",
                "--key-file=id_dsa",
                "--key-size",
                "1024",
                "--key-type",
                "dsa",
                "--key-skip",
            ]
        )

        self.assertNamespaceEqual(
            {
                "sub_command": "key-gen",
                "key_comment": "some comment",
                "key_file": "id_dsa",
                "key_size": 1024,
                "key_password": None,
                "key_type": "dsa",
                "key_format": "openssh_v1",
                "key_skip": True,
            },
            options,
        )

    def test_default_overwrite(self):
        """
        You can change default values.
        """
        generate_ssh_key_parser(
            self.subparser,
            "key-gen",
            default_key_type="dsa",
        )

        options = self.parseArguments(["key-gen"])

        self.assertNamespaceEqual(
            {
                "sub_command": "key-gen",
                "key_comment": None,
                "key_file": None,
                "key_size": None,
                "key_password": None,
                "key_type": "dsa",
                "key_format": "openssh_v1",
                "key_skip": False,
            },
            options,
        )


class Testgenerate_ssh_key(ChevahTestCase, CommandLineMixin):
    """
    Tests for generate_ssh_key.
    """

    def setUp(self):
        super(Testgenerate_ssh_key, self).setUp()
        self.parser = ArgumentParser(prog="test-command")
        self.sub_command_name = "gen-ssh-key"
        subparser = self.parser.add_subparsers(
            help="Available sub-commands", dest="sub_command"
        )
        generate_ssh_key_parser(subparser, self.sub_command_name)

    def assertPathEqual(self, expected, actual):
        """
        Check that pats are equal.
        """
        self.assertEqual(expected, actual)

    def test_generate_ssh_key_custom_values(self):
        """
        When custom values are provided, the key is generated using those
        values.
        """
        file_name = mk.ascii()
        file_name_pub = file_name + ".pub"
        options = self.parseArguments(
            [
                self.sub_command_name,
                "--key-size=2048",
                "--key-type=DSA",
                "--key-file=" + file_name,
                "--key-comment=this is a comment",
            ]
        )
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(options, open_method=open_method)

        self.assertEqual(
            'SSH key of type "ssh-dss" and length "2048" generated as '
            "openssh_v1 public "
            'key file "%s" and private key file "%s" '
            "without comment as not supported by the output format."
            % (file_name_pub, file_name),
            message,
        )
        self.assertEqual(0, exit_code)

        self.assertEqual("DSA", key.type())
        self.assertEqual(2048, key.size())

        # First it writes the private key.
        first_file = open_method.calls.pop(0)

        self.assertPathEqual(file_name, first_file["path"])
        self.assertEqual("wb", first_file["mode"])
        # OpenSSH V1 format has a random value generated when storing
        # the private key.
        self.assertStartsWith(
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n" b"b3BlbnNzaC1r",
            first_file["stream"].getvalue(),
        )

        # Second it writes the public key.
        second_file = open_method.calls.pop(0)
        self.assertPathEqual(file_name_pub, second_file["path"])
        self.assertEqual("wb", second_file["mode"])
        self.assertEqual(
            key.public().toString("openssh_v1"), second_file["stream"].getvalue()
        )

    def test_generate_ssh_key_default_values(self):
        """
        When no path and no comment are provided, it will use default
        values.
        """
        options = self.parseArguments(
            [
                self.sub_command_name,
                "--key-size=1024",
                "--key-type=RSA",
            ]
        )
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(options, open_method=open_method)

        # Message informs what default values were used.
        self.assertEqual(
            'SSH key of type "ssh-rsa" and length "1024" generated as '
            "openssh_v1 public "
            'key file "id_rsa.pub" and private key file "id_rsa" without '
            "a comment.",
            message,
        )

        self.assertEqual("RSA", key.type())
        self.assertEqual(1024, key.size())

        # First it writes the private key.
        first_file = open_method.calls.pop(0)
        self.assertPathEqual("id_rsa", first_file["path"])
        self.assertEqual("wb", first_file["mode"])
        self.assertStartsWith(
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            b"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA",
            first_file["stream"].getvalue(),
        )

        # Second it writes the public key.
        second_file = open_method.calls.pop(0)
        self.assertPathEqual("id_rsa.pub", second_file["path"])
        self.assertEqual("wb", second_file["mode"])
        self.assertEqual(
            key.public().toString("openssh"), second_file["stream"].getvalue()
        )

    def test_generate_ssh_key_private_exist_no_migration(self):
        """
        When no migration is done it will not generate the key,
        if private file already exists and exit with error.
        """
        self.test_segments = mk.fs.createFileInTemp()
        path = mk.fs.getRealPathFromSegments(self.test_segments)
        options = self.parseArguments(
            [
                self.sub_command_name,
                "--key-type=RSA",
                "--key-size=2048",
                "--key-file",
                path,
            ]
        )
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(options, open_method=open_method)

        self.assertEqual(1, exit_code)
        self.assertEqual("Private key already exists. %s" % path, message)
        # Open is not called.
        self.assertIsEmpty(open_method.calls)

    def test_generate_ssh_key_private_exist_skip(self):
        """
        On skip, will not generate the key if private file already
        exists and exit without error.
        """
        self.test_segments = mk.fs.createFileInTemp()
        path = mk.fs.getRealPathFromSegments(self.test_segments)
        options = self.parseArguments(
            [
                self.sub_command_name,
                "--key-skip",
                "--key-type=RSA",
                "--key-size=2048",
                "--key-file",
                path,
            ]
        )
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(options, open_method=open_method)

        self.assertEqual(0, exit_code)
        self.assertEqual("Key already exists.", message)
        # Open is not called.
        self.assertIsEmpty(open_method.calls)

    def test_generate_ssh_key_public_exist(self):
        """
        Will not generate the key, if public file already exists.
        """
        self.test_segments = mk.fs.createFileInTemp(suffix=".pub")
        path = mk.fs.getRealPathFromSegments(self.test_segments)
        options = self.parseArguments(
            [
                self.sub_command_name,
                "--key-type=RSA",
                "--key-size=2048",
                # path is for public key, but we pass the private path.
                "--key-file",
                path[:-4],
            ]
        )
        open_method = DummyOpenContext()

        exit_code, message, key = generate_ssh_key(options, open_method=open_method)

        self.assertEqual(1, exit_code)
        self.assertEqual("Public key already exists. %s" % path, message)
        # Open is not called.
        self.assertIsEmpty(open_method.calls)

    def test_generate_ssh_key_fail_to_write(self):
        """
        Will return an error when failing to write the key.
        """
        options = self.parseArguments(
            [
                self.sub_command_name,
                "--key-type=RSA",
                "--key-size=1024",
                "--key-file",
                "no-such-parent/ssh.key",
            ]
        )

        exit_code, message, key = generate_ssh_key(options)

        self.assertEqual(1, exit_code)
        self.assertEqual(
            "[Errno 2] No such file or directory: 'no-such-parent/ssh.key'", message
        )
