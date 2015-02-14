chevah-keycert
==============

SSH Keys and SSL certificates handling.

Build development environment::

    make deps

Run tests::

    make test

Default virtual environment is created in build/venv.

This SSH key handling is based on twisted.conch.ssh.key but it was forked
to not depend on Twisted.

It still depends on these C modules:

* pyCrypto
* pyOpenSSL

It provides the following functionalities:

* Generate self signed SSL certificate.
* Generate RSA/DSA keys
* Convert OpenSSH, SSH.com, Putty, LSH

Release is done automatically for each tag, using Travis-CI.

.. image:: https://travis-ci.org/chevah/chevah-keycert.svg?branch=master
    :target: https://travis-ci.org/chevah/chevah-keycert
