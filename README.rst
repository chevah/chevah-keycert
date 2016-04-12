chevah-keycert
==============

SSH Keys and SSL key/csr/certificates handling.

The functions are designed to integrate with command line tools but also with
other user interfaces (for example from a web based control panel).

It depends on these C modules:

* pyCrypto
* pyOpenSSL

It provides the following functionalities:

* Generate SSL key and self signed SSL certificate signed with SHA1.
* Generate SSL key and CSR. Signed with SHA256 or fall back to SHA1.
* Generate RSA/DSA keys.
* Convert OpenSSH, SSH.com, Putty, LSH.
* Populate an argparser subparser with command line options.

The SSH key handling was forked from Twisted code, but project no longer
depends on Twisted.

MIT License.

Release is done automatically for each tag, using Travis-CI.

.. image:: https://pypip.in/version/chevah-keycert/badge.svg
    :target: https://pypi.python.org/pypi/chevah-keycert/
    :alt: Latest Version

.. image:: https://travis-ci.org/chevah/chevah-keycert.svg?branch=master
    :target: https://travis-ci.org/chevah/chevah-keycert

.. image:: https://codecov.io/github/chevah/chevah-keycert/coverage.svg?branch=master
    :target: https://codecov.io/github/chevah/chevah-keycert?branch=master
