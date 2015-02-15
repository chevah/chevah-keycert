chevah-keycert
==============

SSH Keys and SSL certificates handling.

Build development environment and activate it::

    make deps
    . build/venv/bin/activate

Run default tests::

    python setup.py test

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

SSH key handling is based on Twisted code, but project no longer depend
on Twisted.

MIT License.

Release is done automatically for each tag, using Travis-CI.

.. image:: https://pypip.in/version/chevah-keycert/badge.svg
    :target: https://pypi.python.org/pypi/chevah-keycert/
    :alt: Latest Version

.. image:: https://travis-ci.org/chevah/chevah-keycert.svg?branch=master
    :target: https://travis-ci.org/chevah/chevah-keycert

.. image:: https://img.shields.io/coveralls/chevah/chevah-keycert/master.svg
    :target: https://coveralls.io/r/chevah/chevah-keycert?branch=master
