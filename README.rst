chevah-keycert
==============

SSH Keys and SSL key/csr/certificates handling.

The functions are designed to integrate with command line tools but also with
other user interfaces (for example from a web based control panel).

It depends on cryptography.

It provides the following functionalities:

* Generate SSL key and self signed SSL certificate signed with SHA1.
* Generate SSL key and CSR. Signed with SHA256 or fall back to SHA1.
* Generate RSA/DSA/ECDSA/ED keys.
* Convert OpenSSH, SSH.com, Putty.
* Read SSH public keys from X.509 PEM Certificate
* Read SSH public and private keys from PKCS#1 PEM
* Read SSH private keys from PKCS#8 PEM
* Read OpenSSH v1 (new format) private keys
* Populate an argparser subparser with command line options.

The SSH key handling was forked from Twisted code, but project no longer
depends on Twisted.

MIT License.

Release is done automatically for each tag, using Travis-CI.

.. image:: https://img.shields.io/pypi/v/chevah-keycert.svg
    :target: https://pypi.python.org/pypi/chevah-keycert/
    :alt: Latest Version

.. image:: https://travis-ci.org/chevah/chevah-keycert.svg?branch=master
    :target: https://travis-ci.org/chevah/chevah-keycert

.. image:: https://codecov.io/github/chevah/chevah-keycert/coverage.svg?branch=master
    :target: https://codecov.io/github/chevah/chevah-keycert?branch=master
